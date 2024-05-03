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
import atexit
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

class TunnelClinet():
    def __init__(self,clientID,udpdst,clientIP,loginAnswer,id,seq):
        self.udpdst = udpdst
        self.clientIP = clientIP
        self.clientID = clientID
        self.not_clientID = bytes(x^255 for x in clientID)
        self.loginAnswer = loginAnswer
        self.id = id
        self.seq = c_uint16_calc(seq)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect(self.udpdst)
        self.lastseen = time.time()
    def __del__(self):
        self.sock.close()
    def fileno(self):
        return self.sock.fileno()

class UDPTunnelServer():
    def __init__(self,conndst,pwd,AESpwd,MTU):
        self.mtu = MTU
        self.icmptun = RawICMPtunnel(AESpwd)
        self.pwd = hashlib.md5(pwd).digest()
        self.udpdst = conndst.split(":")
        self.udpdst = (self.udpdst[0], int(self.udpdst[1]))
    def run(self):
        self.icmpfd = self.icmptun.sock
        self.pending_clients = {}
        self.clients = {}
        while True:
            rset = select.select([self.icmpfd] + list(self.clients.values()), [], [])[0]
            for r in rset:
                # packet from external (client --> server)
                if r == self.icmpfd:
                    pack = self.icmptun.recv()
                    if pack.type != 8:
                        continue
                    if len(pack.data) < CLIENTID_LEN:
                        continue
                    key = pack.src + str(pack.id)
                    data = pack.data
                    clientID, payload = data[:CLIENTID_LEN], data[CLIENTID_LEN:]
                    if clientID in self.clients:
                            # Simply write the packet to local or forward them to other clients ???
                            client = self.clients[clientID]
                            client.id = pack.id
                            client.seq = c_uint16_calc(pack.seq)
                            os.write(client.fileno(), payload)
                            if client.clientIP != pack.src:
                                client.clientIP = pack.src
                                print(f"client { clientID } roaming to { pack.src }")
                            client.lastseen = time.time()
                    elif clientID in self.pending_clients:
                        # existing client
                        client = self.pending_clients[clientID]
                        if payload.startswith(b"loginAnswer:" + client.loginAnswer):
                            print(f"Login success from {pack.src}:{ str(pack.id)}, clientID: {clientID}")
                            payload = "Login Success."
                            self.clients[clientID] = client
                        else:
                            payload = "Login Failed, wrong answer"
                        print(payload)
                        self.icmptun.send(pack.src, client.not_clientID + payload.encode("utf8"),pack.id,pack.seq)
                        del self.pending_clients[clientID]
                    else:
                        #New client
                        if clientID == b'\0' *CLIENTID_LEN and payload.startswith(b"Login Request from clientID:"):
                            clientID = base64.b64decode(payload.split(b":")[1])
                            loginChallange = randomString(64).encode("utf8")
                            loginAnswer    = base64.b64encode(hashlib.sha256(loginChallange + self.pwd).digest())
                            client =  TunnelClinet(clientID, self.udpdst ,pack.src,loginAnswer,pack.id,pack.seq)
                            self.pending_clients[clientID] = client
                            try:
                                del self.clients[clientID]
                                print(f"Re-login from {clientID}")
                            except KeyError:
                                pass
                            print(f"Login request from {pack.src}:{pack.id}, clientID:{clientID}")
                            payload = b"Login Challange:" + loginChallange
                            print("Answer is:" + loginAnswer.decode("utf8"))
                            self.icmptun.send(pack.src,client.not_clientID + payload,pack.id,pack.seq)
                        else:
                            print("Normal ping from %s:%d" % (pack.src, pack.id))
                            self.icmptun.send(pack.src, pack.data_raw,pack.id,pack.seq,encrypt=False)
                else:
                    # packet from internal (server --> client)
                    client = r
                    data = os.read(r.fileno(), self.mtu )
                    client.lastseen = time.time()
                    self.icmptun.send(client.clientIP,client.not_clientID + data,client.id ,client.seq.intvalue())
                    client.seq += c_uint16_calc(1)
    def close(self):
        pass

try:
    if len(sys.argv) < 5:
        print("Usage: " + sys.argv[0] + " backend_server client_password AES_CTR_password MTU")
        print("Example: " + sys.argv[0] + " 127.0.0.1:51820 client_password AES-CTR_password 1400")
        exit()
    backend_server = sys.argv[1]
    client_password = sys.argv[2].encode("utf8")
    AES_CTR_password = sys.argv[3].encode("utf8")
    MTU = int(sys.argv[4])
    tun = UDPTunnelServer(backend_server,client_password,AES_CTR_password,MTU)
    with open('/proc/sys/net/ipv4/icmp_echo_ignore_all', 'r') as file:
        icmp_echo_ignore_all_initial_value = file.read().strip()
    with open('/proc/sys/net/ipv4/icmp_echo_ignore_all', 'w') as file:
        file.write('1\n')
    atexit.register(lambda: open('/proc/sys/net/ipv4/icmp_echo_ignore_all', 'w').write(icmp_echo_ignore_all_initial_value + '\n'))
    tun.run()
except KeyboardInterrupt:
    tun.close()
    sys.exit(0) 
