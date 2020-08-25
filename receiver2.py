from scapy.all import *

def pkt_callback(pkt):
    if pkt.haslayer("TCP"):
        if pkt.haslayer("Raw"):
            print("[+] Received Message: "+str(pkt[Raw].load))

print("[+] Started Listener")

sniff(iface="wlan0",prn=pkt_callback,filter='icmp',store=0)
