from scapy.all import *

def pkt_callback(pkt):
    if pkt.haslayer("TCP") and pkt.haslayer("Raw"):
        msg = str(pkt[Raw].load)
        if msg[0] == chr(171) or msg[1] == chr(171):
            print("[+] Received Message: "+str(pkt[Raw].load))

print("[+] Started Listener")

sniff(iface="ens4",prn=pkt_callback,filter='host 10.128.15.239',store=0)
