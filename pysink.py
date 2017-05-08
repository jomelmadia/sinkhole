#! /usr/bin/env python
####################################
## pysink, a Python sinkhole script
##
## inspired by IPtrap2
## (https://github.com/jedisct1/iptrap)
## built with Scapy
## (https://github.com/secdev/scapy)
####################################

import sys, getopt
from scapy.all import *

answering_machines = []
sink_if = 'eth1'
sink_ip = '192.168.0.253'

class ICMP_am:
  IP_addr = None

  def __init__(self, ip=None):
    self.IP_addr = ip

  def is_request(self, p):
    if (p.haslayer(IP) and
        p.getlayer(IP).dst == self.IP_addr):
      return True

  def make_reply(self, p):
    ether = p.getlayer(Ether)
    ip = p.getlayer(IP)
    icmp = p.getlayer(ICMP)
    icmp.type = "echo-reply"
    rep = Ether(dst=ether.src)/IP(dst=ip.src, src=ip.dst, proto="icmp")/icmp
    return rep

class TCP_am:
  def is_request(self, p):
    return False

  def make_reply(self, p):
    return p

spin = [ '-', '\\', '|', '/' ]
spos = 0
def filter(p):
  global answering_machines
  global spin
  global spos
  for am in answering_machines:
    if am.is_request(p):
      r = am.make_reply(p)
      print "\nA: ", p.summary(), "\n\t", r.summary()
      sendp(r, iface=sink_if)
      return
  print spin[spos], "\r",
  sys.stdout.flush()
  spos = (spos+1) % len(spin)

def bail():
  print 'pysink.py [-i <sink IF>] [-a <sink IP>]'
  sys.exit(1)

def main(argv):
  global answering_machines
  global sink_if
  global sink_ip
  try:
    opts, args = getopt.getopt(argv, "hi:a:")
  except getopt.GetoptError:
    bail()
  for opt, arg in opts:
    if opt == '-h':
      bail()
    elif opt == '-i':
      sink_if = arg
    elif opt == '-a':
      sink_ip = arg
  print 'Sinking traffic from ', sink_if, ' as IP ', sink_ip
  sink_mac = get_if_hwaddr(sink_if)
  answering_machines = [ ARP_am(IP_addr=sink_ip, ARP_addr=sink_mac), ICMP_am(sink_ip), TCP_am() ]
  sniff(iface=sink_if, prn=filter)

if __name__ == "__main__":
  main(sys.argv[1:])
