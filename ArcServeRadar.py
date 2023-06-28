#!/usr/bin/env python3

# ArcServeRadar by Juan Manuel Fernandez (@TheXC3LL) - MDSec

import sys
import threading
from scapy.all import *

udp_packet = bytearray.fromhex("0441524353455256455f415050") # ARCSERVE_APP

def ping(ip, iface, port):   
    print("[*] Broadcasting")
    sendp(Ether()/IP(src=ip,dst="255.255.255.255")/UDP(dport=1434,sport=port)/Raw(load=udp_packet), verbose=False, iface=iface)

def check(pkt):
	origin = pkt[IP].src
	content = pkt[Raw].load
	if content != udp_packet:
		data = content[content.find(b"Server"):]
		print("\t[+] " + origin + " => " + data.decode("utf-8"))



def monitor(iface, port):
	print("[*] Starting to monitor")
	sniff(prn=check, filter="port " + str(port), iface=iface)

if __name__ == "__main__":
    print("\t\t-=[ ArcServe Finder - @TheXC3LL - MDSec]=-\n\n")
    if len(sys.argv) != 4:
        print("[!] Error. Usage: python3 ArcServeRadar.py <interface> <originport> <originip>")
        exit(-1)
    iface = sys.argv[1]
    port = int(sys.argv[2])
    ip = sys.argv[3]
    x = threading.Thread(target=monitor, args=(iface,port,))
    x.start()
    ping(ip, iface, port)
