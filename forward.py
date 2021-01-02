from scapy.all import *
import sys
import json


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
    print("python forward.py <-t Target IP|-T Targets file> [-r rule] [-i Interface]\r\n",end="")

def getTargets(options):
    if "-T" not in options:
        if "-t" not in options:
            return None
        else:
            return {options["-t"]}
    else:
        targets=set()
        with open(options["-T"],"r") as f:
            for each in f:
                targets.add(each[:len(each)-1])
        return targets

def reSend(pkt):
    pkt[Ether].src=get_if_hwaddr(iface)
    pkt[Ether].dst=None
    sendp(pkt,iface=iface)

def check(pkt):
    if pkt[IP].src in targets or pkt[IP].dst in targets:
        if DNS in pkt:
            return True
        if mode=="black":
            if pkt[IP].src==targets:
                return pkt[IP].dst not in IP_list
            else:
                return pkt[IP].src not in IP_list
        else:
            if pkt[IP].src==targets:
                return pkt[IP].dst in IP_list
            else:
                return pkt[IP].src in IP_list

def has_pkt(pkt):
    if IP in pkt:
        if pkt[Ether].dst==get_if_hwaddr(iface) and pkt[IP].dst!=get_if_addr(iface):
            if check(pkt):
                if pkt[IP].src in targets:
                    print("%s up %d\r\n"%(pkt[IP].src,len(pkt)))
                if pkt[IP].dst in targets:
                    print("%s down %d\r\n"%(pkt[IP].dst,len(pkt)))
                reSend(pkt)

conf.verb=0
options=getOptions()
targets=
rule_json=options.get("-r")
iface=options.get("-i")
if target==None:
    printHelp()
    exit(0)
if rule_json==None:
    rule_json="{\"mode\":\"black\",\"IP_list\":[]}"
if iface==None:
    iface=conf.iface
rule=json.loads(rule_json)
mode=rule["mode"]
IP_list=set()
for each in rule["IP_list"]:
    IP_list.add(each)
sniff(prn=has_pkt,iface=iface)
