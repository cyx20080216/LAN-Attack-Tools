from scapy.all import *
import sys


conf.verb=0
arglen=len(sys.argv)
if arglen<4:
	print("Arg Error")
	exit()
pkt=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[2],op="who-has")
res=srp(pkt,timeout=float(sys.argv[3]),iface=sys.argv[4] if arglen>=5 else conf.iface)
with open(sys.argv[1],"w") as f:
	for each in res[0]:
		f.write("%s\n"%(each[1][ARP].psrc))
