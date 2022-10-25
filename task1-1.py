# Task 1.1 ----------------------------------------------------
#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
  pkt.show()

# The interface can be found with
# 'docker network ls' in the VM
# or 'ifconfig' in the containner
pkt = sniff(iface='br-c93733e9f913', filter='icmp', prn=print_pkt)  
