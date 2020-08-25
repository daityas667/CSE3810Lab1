import random
from scapy.all import *

conf.iface="wlan0"

dst = "192.168.1.100"
msg = "adastra per explotium"

random.seed()
msg_segs = []
seg = []

for char in msg:
    seg.append(char)
    flag = random.randint(1, 3)
    if flag == 3:
        msg_segs.append(seg)
        seg = []

seg = []
for seg in msg_segs:
    seg.insert(0,chr(171))
    seg.insert(0,chr(172))

pkt = IP(dst=dst)/ICMP()/Raw(load=msg)
send(pkt)
