#! /usr/bin/env python
# Raw socketry in Python, see if it's quicker than Scapy!

import sys, getopt, time, hashlib, struct, random
import socket, fcntl

SIOCGIFHWADDR  = 0x8927
def get_if_hwaddr(iff):
  s = socket.socket()
  r = fcntl.ioctl(s, SIOCGIFHWADDR, struct.pack("16s16x", iff))
  s.close()
  return struct.unpack("18x6s8x", r)[0]

def checksum(bits):
  sum = 0
  for w in bits:
    sum += w
  sum = (sum & 0xffff) + ((sum >> 16) & 0xffff)
  return (~sum) & 0xffff

class BasePacket:
  def __str__(self):
    return self.format()

class Ether(BasePacket):
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

  def reply(self, mac = None):
    rep = Ether()
    rep.dst = self.src
    rep.src = mac if mac else self.dst
    rep.pro = self.pro
    return rep

  def format(self):
    return "Ether(dst={0},src={1},pro={2:04x})".format(self.dst.encode('hex'), self.src.encode('hex'), self.pro)

class ARP(BasePacket):
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

  def reply(self, mac = None, ip = None):
    rep = ARP()
    rep.htp = self.htp
    rep.ptp = self.ptp
    rep.hln = self.hln
    rep.pln = self.pln
    rep.opn = 2
    rep.sha = mac if mac else self.tha
    rep.spa = ip if ip else self.tpa
    rep.tha = self.sha
    rep.tpa = self.spa
    return rep

  def format(self):
    return "ARP(htp={0},ptp={1:04x},hln={2},pln={3},opn={4},sha={5},spa={6},tha={7},tpa={8})".format(
      self.htp,
      self.ptp,
      self.hln,
      self.pln,
      self.opn,
      self.sha.encode('hex'),
      socket.inet_ntoa(self.spa),
      self.tha.encode('hex'),
      socket.inet_ntoa(self.tpa)
    )

class IP(BasePacket):
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

  def reply(self, ip = None, len = None):
    rep = IP()
    rep.ver = self.ver
    rep.ihl = 5
    rep.tos = self.tos
    rep.len = 20 + (len if len else 0)
    rep.idn = self.idn
    rep.flg = 0
    rep.frg = 0
    rep.ttl = self.ttl
    rep.pro = self.pro
    rep.chk = 0
    rep.src = ip if ip else self.dst
    rep.dst = self.src
    rep.chk = checksum(struct.unpack("!HHHHHHHHHH", rep.encode()[0:20]))
    return rep

  def format(self):
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
      socket.inet_ntoa(self.src),
      socket.inet_ntoa(self.dst),
      self.opt.encode('hex')
    )

class ICMP(BasePacket):
  def __init__(self, pkt = None):
    self.typ = 8
    self.cod = 0
    self.chk = 0
    self.roh = 0
    self.dat = ''
    if pkt:
      self.decode(pkt)

  def decode(self, pkt):
    if len(pkt) >= 8:
      bits = struct.unpack("!BBHI", pkt[0:8])
      self.typ = bits[0]
      self.cod = bits[1]
      self.chk = bits[2]
      self.roh = bits[3]
      l = len(pkt)
      if l>8:
        self.dat = pkt[8:]
      return pkt[l:]
    return pkt

  def encode(self):
    return struct.pack("!BBHI", self.typ, self.cod, self.chk, self.roh) + self.dat

  def reply(self):
    rep = ICMP()
    rep.typ = 0
    rep.cod = 0
    rep.chk = 0
    rep.roh = self.roh
    rep.dat = self.dat
    return rep

  def format(self):
    return "ICMP(typ={0},cod={1},chk={2},roh={3},dat={4}".format(
      self.typ, self.cod, self.chk, self.roh, self.dat.encode('hex')
    )

class TCP(BasePacket):
  def __init__(self, pkt = None):
    self.src = 1234
    self.dst = 80
    self.seq = 0
    self.ack = 0
    self.dat = 5
    self.res = 0
    self.flg = 0
    self.win = 0
    self.chk = 0
    self.urg = 0
    self.opt = ''
    if pkt:
      self.decode(pkt)

  def decode(self, pkt):
    if len(pkt) >= 20:
      bits = struct.unpack("!HHIIBBHHH", pkt[0:20])
      self.src = bits[0]
      self.dst = bits[1]
      self.seq = bits[2]
      self.ack = bits[3]
      self.dat = (bits[4] >> 4)
      self.res = (bits[4] >> 1)
      self.flg = bits[5]
      self.win = bits[6]
      self.chk = bits[7]
      self.urg = bits[8]
      l = self.dat * 4
      if l > 20 and l <= len(pkt):
        self.opt = pkt[20:l]
        return pkt[l:]
      return pkt[20:]
    return pkt

  def encode(self):
    return struct.pack("!HHIIBBHHH",
      self.src,
      self.dst,
      self.seq,
      self.ack,
      (self.dat << 4),	# NB: we do not encode reserved bits
      self.flg,
      self.win,
      self.chk,
      self.urg
    ) + self.opt

  def reply(self, flag = None, opts = None):
    rep = TCP()
    rep.src = self.dst
    rep.dst = self.src
    rep.seq = random.randint(0, 0xffffffff)
    rep.ack = self.seq + 1
    rep.res = 0
    rep.flg = flag if flag else 0
    rep.win = self.win
    rep.chk = 0
    rep.urg = 0
    # Options, padded to 32-bit multiple
    if opts:
      rep.opt = opts.ljust(((len(opts)+3)/4)*4, '\0')
      rep.dat = 5 + len(rep.opt)/4
    else:
      rep.opt = ''
      rep.dat = 5
    return rep

  def checksum(self, ip):
    # Fake header for checksum calc (why TCP, just WHY!?)
    tmp = list(struct.unpack("!HHHHHH", struct.pack("!4s4sBBH", ip.src, ip.dst, 0, 6, self.dat*4)))
    # actual TCP header..
    tmp = tmp + list(struct.unpack("!HHHHHHHHHH", self.encode()[0:20]))
    # Option data..
    for b in range(0, self.dat-5):
      w = struct.unpack("!HH", self.opt[b*4:b*4+4])
      tmp = tmp + [w[0],w[1]]
    self.chk = checksum(tmp)

  def format(self):
    return "TCP(src={0},dst={1},seq={2},ack={3},dat={4},flg=0x{5:02X},win={6},chk={7},urg={8})".format(
      self.src,
      self.dst,
      self.seq,
      self.ack,
      self.dat,
      self.flg,
      self.win,
      self.chk,
      self.urg
    )

## main program ##

verb = 0
sink_if = 'eth1'
sink_ip = '192.168.0.253'
sink_cnt = 0

spinner = ["-\r", "\\\r", "|\r", "/\r"]
spinpos = 0

def bail():
  print 'usage: raw.py [-h] [-v|q] [-i <if>] [-a <addr>]'
  sys.exit(0)

def msg(*txts):
  if verb > 0:
    sys.stdout.write(" ".join(map(lambda t: t.__str__(), txts)))

def main(argv):
  global sink_if
  global sink_ip
  global sink_cnt
  global spinner
  global spinpos
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
  bin_ip = socket.inet_aton(sink_ip)
  bin_hw = get_if_hwaddr(sink_if)
  raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x3))
  raw.bind((sink_if, 0))
  while True:
    rep = None
    rds = None
    pkt = raw.recv(2048)
    sink_cnt += 1
    if verb >= 0:
      print sink_cnt,": ",
    eth = Ether()
    pkt = eth.decode(pkt)
    msg ( eth )
    if 0x800 == eth.pro:
      ip = IP()
      pkt = ip.decode(pkt)
      msg ( ip )
      if 1 == ip.pro:
        icmp = ICMP()
        pkt = icmp.decode(pkt)
        msg ( icmp )
        if 8 == icmp.typ and cmp(bin_ip, ip.dst) == 0:
          rcp = icmp.reply().encode()
          rep = eth.reply(bin_hw).encode() + ip.reply(bin_ip, len(rcp)).encode() + rcp
          rds = 'ICMP'
      elif 6 == ip.pro:
        tcp = TCP()
        pkt = tcp.decode(pkt)
        msg ( tcp )
        if cmp(bin_ip, ip.dst) == 0:
          synack = tcp.flg & 18
          if 2 == synack:
            # SYN only, reply with SYN+ACK
            tcr = tcp.reply(18, struct.pack("!BBHB", 2,4,1460,0))
            ipr = ip.reply(bin_ip, len(tcr.encode()))
            tcr.checksum(ipr)
            rep = eth.reply(bin_hw).encode() + ipr.encode() + tcr.encode()
            rds = 'TCP(SYNACK)'
          elif 16 == synack and ip.len <= ((ip.ihl+tcp.dat)*4):
            # ACK only, without data, ignore
            rds = 'TCP(ign)'
          else:
            # Anything else, reset
            tcr = tcp.reply(4)
            ipr = ip.reply(bin_ip, len(tcr.encode()))
            tcr.checksum(ipr)
            rep = eth.reply(bin_hw).encode() + ipr.encode() + tcr.encode()
            rds = 'TCP(RST)'
    elif 0x806 == eth.pro:
      arp = ARP()
      pkt = arp.decode(pkt)
      msg ( arp )
      if cmp(bin_ip, arp.tpa) == 0:
        rep = eth.reply(bin_hw).encode() + arp.reply(bin_hw, bin_ip).encode()
        rds = 'ARP'
    if verb > 0:
      print
    elif 0 == verb:
      print spinner[spinpos],
      spinpos = (spinpos+1) % len(spinner)
    sys.stdout.flush()
    if rep:
      msg ( 'Sending reply', rds, "\n" )
      rep = rep.ljust(60, '\0')
      raw.send(rep);

if __name__ == "__main__":
  main(sys.argv[1:])
