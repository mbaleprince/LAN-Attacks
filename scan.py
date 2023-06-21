import scapy.all as scapy

def scan(ip):
        scapy.arping(ip)

scan("172.16.8.1/24")