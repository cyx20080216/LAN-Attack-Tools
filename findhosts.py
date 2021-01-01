from scapy.all import *
import sys


def getOptions():
	options=dict()
	key=None
	for each in sys.argv[1:]:
		if key==None:
				key=each
		else:
			options[key]=each
			key=None
	return options

def printHelp():
	print("python findhosts.py <-f Filename> <-s Segment> [-t Waiting time] [-i Iface]\r\n\n",end="")
	print("\t-f\tA Filename you want to save.\r\n",end="")
	print("\t-s\tYou want to find the segment of the host.\r\n",end="")
	print("\t-t\tHow long you want to wait for the response.\r\n",end="")

conf.verb=0
options=getOptions()
filename=options.get("-f")
segment=options.get("-s")
timeout=options.get("-t")
iface=options.get("-i")
if filename==None:
	print("[!] Arg Error.You must fill in the \"-f\" argument.\r\n",end="")
if segment==None:
	print("[!] Arg Error.You must fill in the \"-f\" argument.\r\n",end="")
if timeout==None:
	timeout="5"
if iface==None:
	iface=conf.iface
if filename==None or segment==None:
	printHelp()
	exit()
pkt=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=segment,op=1)
res=srp(pkt,timeout=float(timeout),iface=iface)
with open(filename,"w") as f:
	for each in res[0]:
		f.write("%s\n"%(each[1][ARP].psrc))
