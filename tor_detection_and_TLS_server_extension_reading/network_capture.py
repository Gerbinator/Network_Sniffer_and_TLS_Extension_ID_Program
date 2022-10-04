from scapy.all import *

ip_address = input("ip address to filter")
location_save = input("where do you want to save this to")
capture = sniff(prn=lambda x:x.summary(), filter=ip_address)
wrpcap(location_save, capture)