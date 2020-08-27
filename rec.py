from scapy.all import *

final_msg = []

def pkt_callback(pkt):
        if pkt.haslayer("TCP"):
                if pkt.haslayer("Raw"):
                        msg = str(pkt[Raw].load)
                        if msg[0] == chr(171) and msg[1] == chr(172):
                                print("[+] Received portion of covert message")
                                final_msg.append(msg[3])
                        elif msg[0] == chr(171) and msg[1] == chr(171):
                                stdout.write("[+] Final message is :")
                                print(final_msg)
                                exit

print("[+] Started Listener")

sniff(iface="ens4",prn=pkt_callback,filter='host 10.128.15.245',store=0)
