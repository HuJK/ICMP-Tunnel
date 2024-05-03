#!/usr/bin/env python3
import socket
import time
import ctypes
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
import traceback
from ctypes import c_uint16

CLIENTID_LEN = 8

class c_uint16_calc:
    def __init__(self, val):
        if type(val) == c_uint16_calc:
            val = val.intvalue()
        self.value = c_uint16(val)
    def __add__(self, other):
        return c_uint16_calc(self.value.value + other.value.value)
    def __sub__(self, other):
        return c_uint16_calc(self.value.value - other.value.value)
    def __repr__(self):
        return f"c_uint16_calc({self.value.value})"
    def intvalue(self):
        return self.value.value

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
        if len(dataarr) < CLIENTID_LEN:
            return b''
        return self.encrypt(dataarr,seqid,struct.unpack("I",counterStart)[0])[4:]

class ICMPtunnel():
    def __init__(self,addr,pwd,AESpwd,clientID):
        self.addr = socket.gethostbyname(addr)
        self.clientID = clientID
        self.not_clientID = bytes(x^255 for x in clientID)
        self.cipher = AEScipher(AESpwd)
        self.pwd = hashlib.md5(pwd).digest()
        self.seq = c_uint16_calc(0)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        self.login(self.pwd)
    def login(self,pwd):
        print("Send Login Request")
        self.sock.settimeout(5)
        try:
            self.send(b"Login Request from clientID:" + base64.b64encode(self.clientID),clientID=b'\0'*CLIENTID_LEN)
            data = self.recv()
            if not data.startswith(b"Login Challange:"):
                raise BaseException("Invalid Response")
            loginChallange = data.split(b":")[1]
            print("Challange received:" , loginChallange)
            ans = base64.b64encode(hashlib.sha256(loginChallange + self.pwd).digest())
            print("Send login answer :" , ans)
            self.send(b"loginAnswer:" + ans)
            data = self.recv()
            if data == b'Login Success.':
                print(data.decode("utf8"))
                self.sock.settimeout(0)
            else:
                raise BaseException("Login failed:", data.decode("utf8"))
        except:
            print("Login Error:")
            print(traceback.format_exc())
            print("Restarting")
            time.sleep(0.5)
            os.execv("/usr/bin/python3", ['python'] + sys.argv)

    def send(self,data,addr = None,clientID=None):
        #print("S",self.seq)
        addr = addr if addr is not None else self.addr
        if clientID == None:
            clientID = self.clientID
        self.sock.sendto(self.pack_packet(clientID + data,self.seq),(addr,0))
        self.seq += c_uint16_calc(1)
    def recv(self):
        return self.recvseq()[0]
    def recvseq(self):
        packet, peer = self.sock.recvfrom(16384)
        seq,data = self.parse_packet(packet)
        not_clientID, payload = data[:CLIENTID_LEN],  data[CLIENTID_LEN:]
        if not_clientID != self.not_clientID:
            print("not_clientID not match, login lost. Restarting")
            time.sleep(0.5)
            os.execv("/usr/bin/python3", ['python'] + sys.argv)
        return payload,seq
    def pack_packet(self,payload,seq):
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        # The checksum is always recomputed by the kernel, and the id is the port number
        header = struct.pack('!bbHHH', 8 ,0, 0, 0, seq.intvalue())
        #print(binascii.hexlify(header))
        return header + self.cipher.encrypt(payload,seq.intvalue())
    def parse_packet(self,data):
        type, code, checksum, packet_id, sequence = struct.unpack('!bbHHH', data[:8])
        return c_uint16_calc(sequence), self.cipher.decrypt(data[8:],sequence)

class UDPTunnelClient():
    def __init__(self,addr,pwd,AESpwd,mtu,clientID,listenPort):
        self.mtu = mtu
        self.icmptun = ICMPtunnel(addr,pwd,AESpwd,clientID)
        self.clientID = clientID
        self.icmpfd = self.icmptun.sock
        self.listenPort = listenPort
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", listenPort ))
        self.downapp_addr = None

    def run(self):
        while True:
            rset = select.select([self.icmpfd, self.sock], [], [])[0]
            for r in rset:
                if r == self.icmpfd:
                    # packet from external (server --> client )
                    data ,seq= self.icmptun.recvseq()
                    if self.downapp_addr == None:
                        print("No downapp")
                        continue
                    if len(data) == 0:
                        continue
                    self.sock.sendto(data, self.downapp_addr)
                elif r == self.sock:
                    # packet from internal (client --> server)
                    payload,remote_addr = self.sock.recvfrom(self.mtu)
                    self.downapp_addr = remote_addr
                    self.icmptun.send(payload)        

    def close(self):
        pass


try:
    if len(sys.argv) < 6:
        print("Usage: " + sys.argv[0] + " remote_server client_password AES_CTR_password MTU listenPort")
        print("Example: " + sys.argv[0] + " example.com client_password AES-CTR_password 1000 51820")
        exit()
    remote_server = sys.argv[1]
    client_password = sys.argv[2].encode("utf8")
    AES_CTR_password = sys.argv[3].encode("utf8")
    MTU = int(sys.argv[4])
    clientID = base64.b64decode(sys.argv[5])
    listenPort = int(sys.argv[6])
    tun = UDPTunnelClient(remote_server,client_password,AES_CTR_password,MTU,clientID,listenPort)
    tun.run()
except KeyboardInterrupt:
    tun.close()
    sys.exit(0)
