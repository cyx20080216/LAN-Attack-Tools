from scapy.all import *
import netifaces
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
    print("python findhosts.py [-t Waiting time] [-i Interface]\r\n",end="")
    print("\t-t\tHow long you want to wait for the response.\r\n",end="")

def IPToInt(IP):
    nums=IP.split(".")
    return int(nums[0])<<24|\
            int(nums[1])<<16|\
            int(nums[2])<<8|\
            int(nums[3])

def intToIP(num):
    return "%d.%d.%d.%d"%(num>>24&0xff,num>>16&0xff,num>>8&0xff,num&0xff)

def lowbit(num):
    return num&(-num)

def getSegment(address,netmask):
    netmask_num=IPToInt(netmask)
    first_address=intToIP(IPToInt(address)&netmask_num)
    bit_num=0
    while netmask_num!=0:
        bit_num+=1
        netmask_num-=lowbit(netmask_num)
    return "%s/%s"%(first_address,bit_num)

conf.verb=0
options=getOptions()
if "--help" in options:
    printHelp()
    exit()
timeout=options.get("-t")
iface=options.get("-i")
if timeout==None:
    timeout="5"
if iface==None:
    iface=conf.iface
address=get_if_addr(iface)
for each in netifaces.interfaces():
    if netifaces.AF_INET in netifaces.ifaddresses(each):
        if netifaces.ifaddresses(each)[netifaces.AF_INET][0]["addr"]==address:
            netmask=netifaces.ifaddresses(each)[netifaces.AF_INET][0]["netmask"]
segment=getSegment(address,netmask)
pkt=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=segment,op=1)
res=srp(pkt,timeout=float(timeout),iface=iface)
for each in res[0]:
    print("%s\r\n"%(each[1][ARP].psrc),end="")
