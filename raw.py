#! /usr/bin/env python
# Raw socketry in Python, see if it's quicker than Scapy!

import sys, getopt, time, hashlib, struct
import socket

def ip2str(ip):
  bits = struct.unpack("!BBBB", ip)
  return "{0}.{1}.{2}.{3}".format(bits[0],bits[1],bits[2],bits[3])

class Ether:
  def __init__(self, pkt = None):
    self.dst = "\xff\xff\xff\xff\xff\xff"
    self.src = "\x00\x00\x00\x00\x00\x00"
    self.pro = 0
    if pkt:
      self.decode(pkt)

  def decode(self, pkt):
    if len(pkt) >= 14:
      bits = struct.unpack("!6s6sH", pkt[0:14])
      self.dst = bits[0]
      self.src = bits[1]
      self.pro = bits[2]
      return pkt[14:]
    return pkt

  def encode(self):
    return struct.pack("!6s6sH", self.dst, self.src, self.pro)

  def __str__(self):
    return "Ether(dst={0},src={1},pro={2:04x})".format(self.dst.encode('hex'), self.src.encode('hex'), self.pro)

class ARP:
  def __init__(self, pkt = None):
    self.htp = 1
    self.ptp = 0x800
    self.hln = 6
    self.pln = 4
    self.opn = 1
    self.sha = "\x00\x00\x00\x00\x00\x00"
    self.spa = "\x00\x00\x00\x00"
    self.tha = "\xff\xff\xff\xff\xff\xff"
    self.tpa = "\xff\xff\xff\xff"
    if pkt:
      self.decode(pkt)

  def decode(self, pkt):
    if len(pkt) >= 28:
      bits = struct.unpack("!HHBBH6s4s6s4s", pkt[0:28])
      self.htp = bits[0]
      self.ptp = bits[1]
      self.hln = bits[2]
      self.pln = bits[3]
      self.opn = bits[4]
      self.sha = bits[5]
      self.spa = bits[6]
      self.tha = bits[7]
      self.tpa = bits[8]
      return pkt[28:]
    return pkt

  def encode(self):
    return struct.pack("!HHBBH6s4s6s4s",
      self.htp,
      self.ptp,
      self.hln,
      self.pln,
      self.opn,
      self.sha,
      self.spa,
      self.tha,
      self.tpa
    )

  def __str__(self):
    return "ARP(htp={0},ptp={1:04x},hln={2},pln={3},opn={4},sha={5},spa={6},tha={7},tpa={8})".format(
      self.htp,
      self.ptp,
      self.hln,
      self.pln,
      self.opn,
      self.sha.encode('hex'),
      ip2str(self.spa),
      self.tha.encode('hex'),
      ip2str(self.tpa)
    )

class IP:
  def __init__(self, pkt = None):
    self.ver = 4
    self.ihl = 5
    self.tos = 0
    self.len = 20
    self.idn = 0
    self.flg = 0
    self.frg = 0
    self.ttl = 255
    self.pro = 0
    self.chk = 0
    self.src = "\x00\x00\x00\x00"
    self.dst = "\xff\xff\xff\xff"
    self.opt = ''
    if pkt:
      self.decode(pkt)

  def decode(self, pkt):
    if len(pkt) >= 20:
      bits = struct.unpack("!BBHHHBBH4s4s", pkt[0:20])
      self.ver = bits[0] >> 4
      self.ihl = bits[0] & 0xf
      self.tos = bits[1]
      self.len = bits[2]
      self.idn = bits[3]
      self.flg = bits[4] >> 13
      self.frg = bits[4] & 0x1fff
      self.ttl = bits[5]
      self.pro = bits[6]
      self.chk = bits[7]
      self.src = bits[8]
      self.dst = bits[9]
      l = self.ihl * 4
      if l > 20 and l <= len(pkt):
        self.opt = pkt[20:l]
        return pkt[l:]
      return pkt[20:]
    return pkt

  def encode(self):
    return struct.pack("!BBHHHBBH4s4s",
      (self.ver << 4) | (self.ihl),
      self.tos,
      self.len,
      self.idn,
      (self.flg << 13) | (self.frg),
      self.ttl,
      self.pro,
      self.chk,
      self.src,
      self.dst
    ) + self.opt

  def __str__(self):
    return "IP(ver={0},ihl={1},tos={2},len={3},idn={4},flg={5},frg={6},ttl={7},pro={8},chk={9},src={10},dst={11},opt={12})".format(
      self.ver,
      self.ihl,
      self.tos,
      self.len,
      self.idn,
      self.flg,
      self.frg,
      self.ttl,
      self.pro,
      self.chk,
      ip2str(self.src),
      ip2str(self.dst),
      self.opt.encode('hex')
    )

verb = 0
sink_if = 'eth1'
sink_ip = '192.168.0.253'

def bail():
  print 'usage: raw.py [-h] [-v|q] [-i <if>] [-a <addr>]'
  sys.exit(0)

def main(argv):
  global sink_if
  global sink_ip
  global verb
  try:
    opts, args = getopt.getopt(argv, "hvqi:a:")
  except getopt.GetoptError:
    bail()
  for opt, arg in opts:
    if opt == '-h':
      bail()
    elif opt == '-v':
      verb = 1
    elif opt == '-q':
      verb = -1
    elif opt == '-i':
      sink_if = arg
    elif opt == '-a':
      sink_ip = arg
  print 'Sinking traffic from ', sink_if, ' as IP ', sink_ip
  raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x3))
  raw.bind((sink_if, 0))
  while True:
    pkt = raw.recv(2048)
    eth = Ether()
    pkt = eth.decode(pkt)
    print eth,
    if 0x800 == eth.pro:
      ip = IP()
      pkt = ip.decode(pkt)
      print ip,
    elif 0x806 == eth.pro:
      arp = ARP()
      pkt = arp.decode(pkt)
      print arp,
    print

if __name__ == "__main__":
  main(sys.argv[1:])
