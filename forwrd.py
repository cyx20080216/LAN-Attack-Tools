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
    print("python forward.py <-t Target IP> [-r rule] [-i Interface]\r\n",end="")

def reSend(pkt):
    pkt[Ether].src=get_if_hwaddr(iface)
    pkt[Ether].dst=None
    sendp(pkt,iface=iface)

def check(pkt):
    if pkt[IP].src==target or pkt[IP].dst==target:
        if DNS in pkt:
            return True
        if mode=="black":
            if pkt[IP].src==target:
                return pkt[IP].dst not in IP_list
            else:
                return pkt[IP].src not in IP_list
        else:
            if pkt[IP].src==target:
                return pkt[IP].dst in IP_list
            else:
                return pkt[IP].src in IP_list

def has_pkt(pkt):
    if IP in pkt:
        if pkt[Ether].dst==get_if_hwaddr(iface) and pkt[IP].dst!=get_if_addr(iface):
            if check(pkt):
                reSend(pkt)

conf.verb=0
options=getOptions()
target=options.get("-t")
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
