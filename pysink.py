#! /usr/bin/env python
####################################
## pysink, a Python sinkhole script
##
## inspired by IPtrap2
## (https://github.com/jedisct1/iptrap)
## built with Scapy
## (https://github.com/secdev/scapy)
####################################

import sys, getopt, time, hashlib, struct
from scapy.all import *

verb = 0
answering_machines = []
sink_if = 'eth1'
sink_ip = '192.168.0.253'

class ICMP_am(AnsweringMachine):
  IP_addr = None

  def parse_options(self, IP_addr=None):
    self.IP_addr = IP_addr

  def is_request(self, p):
    return (p.haslayer(IP) and
            p.getlayer(IP).dst == self.IP_addr and
            p.haslayer(ICMP))

  def make_reply(self, p):
    ether = p.getlayer(Ether)
    ip = p.getlayer(IP)
    icmp = copy.deepcopy(p.getlayer(ICMP))
    icmp.type = "echo-reply"
    rep = Ether(dst=ether.src)/IP(dst=ip.src, src=ip.dst, proto="icmp")/icmp
    return rep

# This is where iptrap2's mechanism is used to avoid keeping any state server-side

class TCP_am(AnsweringMachine):
  def parse_options(self, IP_addr=None):
    self.IP_addr = IP_addr

  def is_request(self, p):
    return (p.haslayer(IP) and
            p.getlayer(IP).dst == self.IP_addr and
            p.haslayer(TCP))

  def reply_tcp(self, p):
    ether = p.getlayer(Ether)
    ip = p.getlayer(IP)
    tcp = p.getlayer(TCP)
    return Ether(dst=ether.src)/IP(dst=ip.src, src=ip.dst, proto="tcp")/TCP(
      sport=tcp.dport, dport=tcp.sport, seq=0, ack=tcp.seq+1, flags=0
    )

  def tstamp(self):
    return int(time.time())/64

  def hash_pkt(self, p):
    ip = p.getlayer(IP)
    tcp = p.getlayer(TCP)
    sha = hashlib.sha1()
    sha.update(str(ip.src))
    sha.update(str(ip.dst))
    sha.update(str(tcp.sport))
    sha.update(str(tcp.dport))
    sha.update(str(self.tstamp()))
    return struct.unpack('<L', sha.digest()[0:4])[0]

  def make_reply(self, p):
    flags = p.getlayer(TCP).flags
    rep = self.reply_tcp(p)
    tcp = rep.getlayer(TCP)

    # We have three cases to process, all determined by TCP flags:

    # SYN only (start of 3-way handshake), we respond with SYN+ACK
    if (flags & 18) == 2:
      tcp.seq = self.hash_pkt(p)
      tcp.flags = "SA"

    # ACK (confirming 3-way handshake, possibly with data), ignore if no data
    elif (flags & 18) == 16:
      if not p.haslayer(Raw):
        return None
      else:
        tcp.seq = self.hash_pkt(p)
        tcp.flags = "RA"

    # anything else (data or other packet type), send RST
    else:
      tcp.seq = self.hash_pkt(p)
      tcp.flags = "R"

    return rep

spin = [ '-', '\\', '|', '/' ]
spos = 0
def filter(p):
  global answering_machines
  global spin
  global spos
  global verb
  for am in answering_machines:
    if am.is_request(p):
      r = am.make_reply(p)
      if r:
        sendp(r, iface=sink_if, verbose=0)
        m = r.summary()
      else:
        m = 'ignored'
      if not verb < 0:
        print "\t< ", p.summary(), "\n\t> ", m
      return
  if verb > 0:
    print "\t[", p.summary(), "]"
  elif verb < 0:
    return
  else:
    print spin[spos], "\r",
    sys.stdout.flush()
    spos = (spos+1) % len(spin)

def bail():
  print 'pysink.py [-h] [-v|q] [-i <sink IF>] [-a <sink IP>]'
  sys.exit(1)

def main(argv):
  global answering_machines
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
  sink_mac = get_if_hwaddr(sink_if)
  # NB: ordered in most likely occurance to reduce processing time
  answering_machines = [
    TCP_am(IP_addr=sink_ip),
    ARP_am(IP_addr=sink_ip, ARP_addr=sink_mac),
    ICMP_am(IP_addr=sink_ip),
  ]
  sniff(iface=sink_if, prn=filter)

if __name__ == "__main__":
  main(sys.argv[1:])
