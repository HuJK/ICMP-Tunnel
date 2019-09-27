#!/usr/bin/env python3
import socket
import time
import struct
import sys
import os
import hashlib
import getopt
import fcntl
import struct
import socket, select
from Crypto.Cipher import AES
import base64
import binascii

class AEScipher():
    def __init__(self,aespwd):
        AESCTR_PASSWORD = hashlib.sha256(aespwd).digest()
        key = AESCTR_PASSWORD[:16]
        self.nonce = AESCTR_PASSWORD[16:24]
        self.cipher = AES.new(key, AES.MODE_ECB)
    def encrypt(self, dataarr , seqid,counterStart = None):
        BCER = b""
        counterStart = counterStart if counterStart is not None else struct.unpack("I",os.urandom(4))[0]
        for i in range(len(dataarr) // 16 + 1):
            counter = struct.pack("IHH", counterStart , i , seqid)
            IVc = self.nonce + counter
            BCER += self.cipher.encrypt(IVc)
        retarr = b""
        for i in range(len(dataarr)):
            retarr += struct.pack("B",(dataarr[i] ^ BCER[i]))
        return struct.pack( "I", counterStart) + retarr
    def decrypt(self, dataarr , seqid):
        counterStart = dataarr[0:4]
        dataarr = dataarr[4:]
        return self.encrypt(dataarr,seqid,struct.unpack("I",counterStart)[0])[4:]

class ICMPtunnel():
    def __init__(self,addr,pwd,AESpwd):
        self.addr = socket.gethostbyname(addr)
        self.cipher = AEScipher(AESpwd)
        self.pwd = hashlib.md5(pwd).digest()
        self.seq = 0
        self.masklen = 24
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        self.LanIP= b"169.254.1.1"
        self.login(self.pwd)
    def login(self,pwd):
        self.send(b"Login Request")
        data = self.recv()
        print(data)
        if not data.startswith(b"Login Challange:"):
            raise BaseException("Invalid Response")
        loginChallange = data.split(b":")[1]
        print(b"Challange received:" + loginChallange)
        ans = base64.b64encode(hashlib.sha256(loginChallange + self.pwd).digest())
        print(b"Send login answer :" + ans)
        self.send(b"loginAnswer:" + ans)
        data = self.recv()
        print(data)
        self.LanIP = data.split(b":")[1]
    def send(self,data,addr = None):
        #print("S",self.seq)
        addr = addr if addr is not None else self.addr
        self.sock.sendto(self.pack_packet(data,self.seq),(addr,0))
        self.seq += 1
    def recv(self):
        packet, peer = self.sock.recvfrom(16384)
        seq,data = self.parse_packet(packet)
        return data
    def recvseq(self):
        packet, peer = self.sock.recvfrom(16384)
        seq,data = self.parse_packet(packet)
        return data,seq
    def pack_packet(self,payload,seq):
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        # The checksum is always recomputed by the kernel, and the id is the port number
        seq = seq % 2**16
        header = struct.pack('!bbHHH', 8 ,0, 0, 0, seq)
        #print(binascii.hexlify(header))
        return header + self.cipher.encrypt(payload,seq)
    def parse_packet(self,data):
        type, code, checksum, packet_id, sequence = struct.unpack('!bbHHH', data[:8])
        return sequence, self.cipher.decrypt(data[8:],sequence)

class Tunnel():
    def __init__(self,addr,pwd,AESpwd,mtu):
        self.mtu = mtu
        self.icmptun = ICMPtunnel(addr,pwd,AESpwd)
        self.icmpfd = self.icmptun.sock
        self.create()
        self.config(self.icmptun.LanIP.decode("utf8"))
        

    def create(self):
        TUNSETIFF   = 0x400454ca
        IFF_TUN     = 0x0001
        self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        ifs = fcntl.ioctl( self.tfd, TUNSETIFF, struct.pack("16sH", b"t%d", IFF_TUN))
        self.tname = ifs[:16].strip(b"\x00").decode("utf8")
        print(self.tname)

    def config(self, ip):
        os.system("ip link set %s up" % (self.tname))
        os.system("ip link set %s mtu %i" % (self.tname,self.mtu))
        os.system("ip addr add %s/%i dev %s" % (ip,self.icmptun.masklen, self.tname))

    def run(self):
        while True:
            rset = select.select([self.icmpfd, self.tfd], [], [])[0]
            for r in rset:
                #print(">",end="")
                # packet from internal (client --> server)
                if r == self.tfd:
                    data = os.read(self.tfd, self.mtu + 500)
                    #print("Send:",binascii.hexlify(data))
                    self.icmptun.send(data)
                # packet from external (client <-- server)
                elif r == self.icmpfd:
                    data ,seq= self.icmptun.recvseq()
                    #print("Recv:",binascii.hexlify(data))
                    #print("R",seq,end="\n")
                    os.write(self.tfd, data)

    def close(self):
        os.close(self.tfd)

try:
    tun = Tunnel("jp.vm.sivilization.com",b"password",b"AES-CTR_password",998)
    tun.run()
except KeyboardInterrupt:
    tun.close()
    sys.exit(0) 
