import random
from scapy.all import *

conf.iface="wlan0"

dest = sys.argv[0]
print(dest)
msg = "adastra per explotium"

def send_packet(seg):
	pkt = IP(dst=dest)/TCP()/Raw(load=seg)
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
				to_send.insert(0,chr(171))
				to_send.insert(0,chr(172))
				send_packet(to_send)
				print("[+] Sent packet containing portion of message")
				sent = True
			else:
				pkt = IP(dst=dest)/TCP()
				sent(pkt)
				print("[+] Sent junk packet")
		sent = False
		
	to_send = ""
	to_send.append(char(171))
	to_send.append(char(171))
	send_packet(to_send) #Sent packet indacating transmission has completed
	print("[+] Done sending message")
		
main()

