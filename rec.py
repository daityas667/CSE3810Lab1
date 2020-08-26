from scapy.all import *

final_msg = []

def pkt_callback(pkt):
    if pkt.haslayer("TCP"):
        if pkt.haslayer("Raw"):
            msg = str(pkt[Raw].load)
			if msg[0] == chr(171) and msg[1] == chr(172): #Rec'd packet contains data from covert message
				print("[+] Received portion of covert message")
				final_msg.append(msg[3])
			else:
				print("[+] Received junk packet from sender")
				

print("[+] Started Listener")

sniff(iface="wlan0",prn=pkt_callback,filter='host 10.128.15.234',store=0)