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
import random

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

class packet():
    src=""
    seq=0
    id=0
    type=0
    data=b""
    data_raw = b""
class RawICMPtunnel():
    def __init__(self,AESpwd):
        self.cipher = AEScipher(AESpwd)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    def send(self,addr,data,id,seq,encrypt=True):
        buf = self.pack_packet(data,id,seq,encrypt=encrypt)
        #print("Send to ", (addr , buf))
        self.sock.sendto(buf,(addr,22))

    def recv(self):
        buf = self.sock.recv(16384)
        return self.parse_packet(buf)
    
    def ICMPchecksum(self,source_string):
        if type(source_string) != bytes:
            raise TypeError("Bust be bytes")
        """
        I'm not too confident that this is right but testing seems
        to suggest that it gives the same answers as in_cksum in ping.c
        """
        sum = 0
        countTo = (len(source_string)//2)*2
        count = 0
        while count<countTo:
            thisVal = (source_string[count + 1])*256 + (source_string[count])
            sum = sum + thisVal
            sum = sum & 0xffffffff # Necessary?
            count = count + 2
        if countTo<len(source_string):
            sum = sum + (source_string[len(source_string) - 1])
            sum = sum & 0xffffffff # Necessary?
        sum = (sum >> 16)  +  (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        # Swap bytes. Bugger me if I know why.
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer
    def pack_packet(self,payload,id,seq,encrypt=True):
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        seq = seq % 2**16
        header = struct.pack('!bbHHH', 0 ,0, 0, id, seq)
        if encrypt==True:
            data = self.cipher.encrypt(payload,seq)
        else:
            data = payload
        chksum = self.ICMPchecksum(header+data)
        return header[0:2] + struct.pack("!H",chksum) + header[4:] + data
    def parse_packet(self,data):
        p = packet()
        #IPttl, IPproto, IPchksum = struct.unpack("!BBH", data[8:12])
        IPsrc, IPdst = socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20])
        ICMPtype, ICMPcode, ICMPchecksum, ICMPpacket_id, ICMPsequence = struct.unpack('!bbHHH', data[20:28])

        calsum = self.ICMPchecksum(data[20:22] + b"\x00\x00" + data[24:])
        if ICMPchecksum != calsum:
            print("checksum not match")
        p.src = IPsrc
        p.type = ICMPtype
        p.id = ICMPpacket_id
        p.seq = ICMPsequence
        p.data_raw = data[28:]
        p.data = self.cipher.decrypt(data[28:],ICMPsequence)
        return p

def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"
    return ''.join(random.choice(letters) for i in range(stringLength))

class TunnelServer():
    def __init__(self,addr,masklen,pwd,AESpwd,mtu):
        self.icmptun = RawICMPtunnel(AESpwd)
        self.pwd = hashlib.md5(pwd).digest()
        self.icmpfd = self.icmptun.sock
        self.masklen = masklen
        self.mask = "255.255.255.0"
        self.ServerIP = addr
        self.clients={}
        self.mtu = mtu
        self.TIMEOUT = 600
        self.create()
        self.config(addr)
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
        os.system("ip addr add %s/%i dev %s" % (ip,self.masklen, self.tname))

    def close(self):
        os.close(self.tfd)

    def ip_str2int(self,ip_str):
        return struct.unpack(">I",struct.pack("BBBB",*map(int,ip_str.split("."))))[0]
    def ip_int2str(self,ip_int):
        if ip_int <0:
            ip_int += 2**32
        return ".".join(map(str,struct.unpack("BBBB",struct.pack(">I",ip_int))))
    def getInUseIP(self):
        InUse_IP = [self.ServerIP]
        for k,c in self.clients.items():
            InUse_IP += [c["LanIP"]]
        return InUse_IP
    def getNextAvailableIp(self):
        IFACE_IPi   = self.ip_str2int(self.ServerIP)
        IFACE_Maski = 2**32 - 2**(32 - self.masklen)
        inUseIP = map(self.ip_str2int,self.getInUseIP())
        for testIP in range(IFACE_Maski+1, 2**32):
            testIP = (IFACE_Maski & IFACE_IPi) | ((2**32-1 ^ IFACE_Maski) & testIP)
            if testIP not in inUseIP:
                return self.ip_int2str(testIP)
        print("No ip available, all ip in ip pool are already in use")
        return "169.254.1.1"

    def run(self):
        self.icmpfd = self.icmptun.sock
        while True:
            rset = select.select([self.icmpfd, self.tfd], [], [])[0]
            for r in rset:
                # packet from internal (client <-- server)
                if r == self.tfd:
                    data = os.read(self.tfd, self.mtu + 500 )
                    for key,val in self.clients.items():
                        self.icmptun.send(val["addr"],data,val["id"],val["seq"])
                        val["seq"] += 1
                    curTime = time.time()
                    for key in self.clients.keys():
                        if curTime - self.clients[key]["aliveTime"] > self.TIMEOUT:
                            print("Remove timeout client", self.clients[key]["addr"])
                            del self.clients[key]
                # packet from external (client --> server)
                elif r == self.icmpfd:
                    pack = self.icmptun.recv()
                    if pack.type != 8:
                        continue
                    key = pack.src + str(pack.id)
                    data = pack.data
                    if key not in self.clients:
                        #New client
                        if data == b"Login Request":
                            loginChallange = randomString(64).encode("utf8")
                            loginAnswer    = base64.b64encode(hashlib.sha256(loginChallange + self.pwd).digest())
                            self.clients[key] = {"aliveTime": time.time(),
                                                    "addr": pack.src,
                                                    "id":   pack.id,
                                                    "seq":pack.seq,
                                                    "loginChallange" : loginChallange,
                                                    "loginAnswer"    : loginAnswer,
                                                    "LanIP"          : "169.254.1.1"
                                            }
                            print("Login request from %s:%d" % (pack.src, pack.id))
                            data = b"Login Challange:" + loginChallange
                            print("Answer is:" + loginAnswer.decode("utf8"))
                            self.icmptun.send(pack.src,data,pack.id,pack.seq)
                        else:
                            print("Normal ping from %s:%d" % (pack.src, pack.id))
                            self.icmptun.send(pack.src,pack.data_raw,pack.id,pack.seq,encrypt=False)
                    else:
                        if self.clients[key]["LanIP"] == "169.254.1.1":
                            if data.startswith(b"loginAnswer:" + self.clients[key]["loginAnswer"]):
                                self.clients[key]["LanIP"] = self.getNextAvailableIp()
                                data = "Login Success. Allocatd IP is :" + self.clients[key]["LanIP"] + "/" + str(self.masklen)
                                print(data)
                                self.icmptun.send(pack.src,data.encode("utf8"),pack.id,pack.seq)
                            else:
                                #print(data)
                                print("wrong answer")
                        else:
                            # Simply write the packet to local or forward them to other clients ???
                            os.write(self.tfd, data)
                            self.clients[key]["aliveTime"] = time.time()
try:
    if len(sys.argv) < 5:
        print("Usage: " + sys.argv[0] + " server_address/mask_length password AES_CTR_password MTU")
        print("Example: " + sys.argv[0] + " 10.99.8.1/24 password AES-CTR_password 1000")
        exit()
    tun = TunnelServer(sys.argv[1].split("/")[0],int(sys.argv[1].split("/")[1]),sys.argv[2].encode("utf8") ,sys.argv[3].encode("utf8"),int(sys.argv[4]))
    tun.run()
except KeyboardInterrupt:
    tun.close()
    sys.exit(0) 
