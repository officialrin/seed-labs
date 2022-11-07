#!/usr/bin/python3
from scapy.all import*

def sniff_spoof(pkt):
  if pkt[ICMP].type != 8:
      return
    
  ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
  icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
  data = pkt[Raw].load
  newpkt = ip/icmp/data
    
  send(newpkt, verbose=0)
  
  print("Sent\n")
  
while(1):
  pkt = sniff(filter='icmp', prn=sniff_spoof)
