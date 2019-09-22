#!/usr/bin/env python
import socket
import binascii
import struct
import ctypes

BUFFER_SIZE = 8192
def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)
class IPPacket():
    def _checksum(self,source_string):
        """
        I'm not too confident that this is right but testing seems
        to suggest that it gives the same answers as in_cksum in ping.c
        """
        sum = 0
        countTo = (len(source_string)/2)*2
        count = 0
        while count<countTo:
            thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
            sum = sum + thisVal
            sum = sum & 0xffffffff # Necessary?
            count = count + 2

        if countTo<len(source_string):
            sum = sum + ord(source_string[len(source_string) - 1])
            sum = sum & 0xffffffff # Necessary?

        sum = (sum >> 16)  +  (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff

        # Swap bytes. Bugger me if I know why.
        answer = answer >> 8 | (answer << 8 & 0xff00)

        return answer
    def parse(self, buf, debug = True):
        self.ttl, self.proto, self.chksum = struct.unpack("!BBH", buf[8:12])
        self.src, self.dst = buf[12:16], buf[16:20]
        if debug:
            print "parse IP ttl=", self.ttl, "proto=", self.proto, "src=", socket.inet_ntoa(self.src), "dst=", socket.inet_ntoa(self.dst)
class ICMPPacket(IPPacket):
    def parse(self, buf, debug = True):
        IPPacket.parse(self, buf, debug)
        self.type, self.code, self.chksum, self.id, self.seqno = struct.unpack("!BBHHH", buf[20:28])
        self.calsum = IPPacket._checksum(self,  buf[20:22] + "\x00\x00" + buf[24:])
        if debug:
            print "parse ICMP type=", self.type, "code=", self.code, "id=", self.id, "seqno=", self.seqno
            print "chksum: " , self.chksum , "\tcalsum: " , self.calsum
        return buf[28:] if self.chksum == self.calsum else ""

    def create(self, type_, code, id_, seqno, data):
        packfmt = "!BBHHH%ss" % (len(data))
        args = [type_, code, 0, id_, seqno, data]
        args[2] = IPPacket._checksum(self, struct.pack(packfmt, *args))
        return struct.pack(packfmt, *args)
