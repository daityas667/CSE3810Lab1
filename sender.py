import random
from scapy.all import *
conf.iface="ens4"

src = "10.128.15.244" #internal ip
dest = "35.239.112.246" #external ip

msg = "adastra per explotium"
def send_packet(seg):
        pkt = IP(src=src,  dst=dest)/TCP()/Raw(load=seg)
        send(pkt)

def main():
        random.seed()

        needed = len(msg)
        num_sent = 0
        sent = False

        while(num_sent < needed):
                to_send = msg[num_sent]
                while(sent == False):
                        flag = random.randint(1,4)
                        if flag == 4:
                                to_send = chr(171) + to_send
                                send_packet(to_send)
                                print("[+] Sent packet containing portion of message")
                                sent = True
                                num_sent += 1
                        else:
                                pkt = IP(dst=dest)/TCP()
                                send(pkt)
                                print("[+] Sent junk packet")
                                sent = False
                sent = False
        print("[+] Done sending message")

main()
