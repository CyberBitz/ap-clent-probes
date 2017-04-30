#!/usr/bin/env python

from scapy.all import *
from datetime import datetime
ap_list=[]
client_list=[]
print "%s %s %s" %("TYPE".ljust(38),"SSID".ljust(30),"TIME") 
def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 8:
			if pkt.addr2 not in ap_list:
				ap_list.append(pkt.addr2)
				print "AP MAC: %s %s %s" %(pkt.addr2.ljust(30), pkt.info.ljust(30),datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 4 :
			if pkt.addr2 not in client_list:
				client_list.append(pkt.addr2)
				clientname = pkt.info
				if not pkt.info:
					pkt.info = "None"
				print "Client: %s %s %s" %(pkt.addr2.ljust(30), pkt.info.ljust(30),datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

sniff(iface="wlan0mon", prn = PacketHandler)
