from scapy.all import *

node_list = []
for line in open("node_list.txt", "r"):
    node_list.append(line.strip().split("|"))


def process(packet):
    # Check if we have an IP layer
    if packet[0].getlayer(IP):
        for node_array in node_list:
            if packet[0].getlayer(IP).dst == node_array[0]:
                print("IP " + packet[0].getlayer(IP).src + " is connected to Tor node: " + ' | '.join(node_array))


sniff(prn=process)