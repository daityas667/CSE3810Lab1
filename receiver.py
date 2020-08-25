from scapy.all import *

def pkt_callback(pkt):
    if pkt.haslayer("TCP"):
        print("[+] Received Message: "+str(pkt[Raw].load))

print("[+] Started Listener")

sniff(iface="ens4",prn=pkt_callback,filter='host 10.128.15.234',store=0)
