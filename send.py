import random
from scapy.all import *

conf.iface="wlan0"

dst = sys.argv[0]
print(dst)
msg = "adastra per explotium"

def send_packet(seg):
	pkt = IP(dst=dst)/TCP()/Raw(load=seg)
	send(pkt)

def main():
	random.seed()
	
	needed = len(msg)
	num_sent = 0
	sent = False
	
	while(num_sent < needed):
		to_send = msg[sent]
		while(!sent):
			flag = random.randrange(1,4)
			if flag == 4:
				send_packet(to_send)
				print("[+] Sent packet containing portion of message")
				sent = True
			else:
				

	seg = []
	for seg in msg_segs:
		to_send.insert(0,chr(171))
		to_send.insert(0,chr(172))
		
main()
