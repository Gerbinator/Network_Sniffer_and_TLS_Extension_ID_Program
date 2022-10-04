from scapy.all import *
logging.getLogger("scapy").setLevel(logging.CRITICAL)

file_location = input()
parser_type = input()


def youtube_id(packet):
    try:
        filter = ["googlevideo", "yt3", "i-ytimg", "ytimg" ,"youtube.com"]
        for x in filter:
            if packet.haslayer(ServerName):
                if x in str(packet[0].getlayer(ServerName).servername):
                    print("Server Name: " + str(packet[0].getlayer(ServerName).servername)
                          + " | Source to Destination IP: " + str(packet[0].getlayer(IP).src)
                          + " -> " + str(packet[0].getlayer(IP).dst) + " | Source to Destination Port: " +
                          str(packet[0].getlayer(TCP).sport) + ' -> ' + str(packet[0].getlayer(TCP).dport))
                    print()
    except AttributeError:
        pass


def facebook_id(packet):
    try:
        filter = ["facebook", "fbcdn.net"]
        for x in filter:
            if packet.haslayer(ServerName):
                if x in str(packet[0].getlayer(ServerName)):
                    print("Server Name: " + str(packet[0].getlayer(ServerName).servername)
                          + " | Source to Destination IP: " + str(packet[0].getlayer(IP).src)
                          + " -> " + str(packet[0].getlayer(IP).dst) + " | Source to Destination Port: " +
                          str(packet[0].getlayer(TCP).sport) + ' -> ' + str(packet[0].getlayer(TCP).dport))
                    print()
    except AttributeError:
        pass


def reddit_id(packet):
    try:
        filter = ["redd.it", "reddit"]
        for x in filter:
            if packet.haslayer(ServerName):
                if x in str(packet[0].getlayer(ServerName)):
                    print("Server Name: " + str(packet[0].getlayer(ServerName).servername)
                          + " | Source to Destination IP: " + str(packet[0].getlayer(IP).src)
                          + " -> " + str(packet[0].getlayer(IP).dst) + " | Source to Destination Port: " +
                          str(packet[0].getlayer(TCP).sport) + ' -> ' + str(packet[0].getlayer(TCP).dport))
                    print()
    except AttributeError:
        pass


def four_chan_id(packet):
    try:
        filter = ["4cdn","4chan"]
        for x in filter:
            if packet.haslayer(ServerName):
                if x in str(packet[0].getlayer(ServerName)):
                    print("Server Name: " + str(packet[0].getlayer(ServerName).servername)
                          + " | Source to Destination IP: " + str(packet[0].getlayer(IP).src)
                          + " -> " + str(packet[0].getlayer(IP).dst) + " | Source to Destination Port: " +
                          str(packet[0].getlayer(TCP).sport) + ' -> ' + str(packet[0].getlayer(TCP).dport))
                    print()
    except AttributeError:
        pass


def discord_id(packet):
    try:
        filter = ["discordapp","discord"]
        for x in filter:
            if packet.haslayer(ServerName):
                if x in str(packet[0].getlayer(ServerName)):
                    print("Server Name: " + str(packet[0].getlayer(ServerName).servername)
                          + " | Source to Destination IP: " + str(packet[0].getlayer(IP).src)
                          + " -> " + str(packet[0].getlayer(IP).dst) + " | Source to Destination Port: " +
                          str(packet[0].getlayer(TCP).sport) + ' -> ' + str(packet[0].getlayer(TCP).dport))
                    print()
    except AttributeError:
        pass


load_layer('tls')
if parser_type == "Facebook":
    scapy_sniff = sniff(offline=file_location, prn=facebook_id)
elif parser_type == "Discord":
    scapy_sniff = sniff(offline=file_location, prn=discord_id)
elif parser_type == "Youtube":
    scapy_sniff = sniff(offline=file_location, prn=youtube_id)
elif parser_type == "Reddit":
    scapy_sniff = sniff(offline=file_location, prn=reddit_id)
elif parser_type == "4chan":
    scapy_sniff = sniff(offline=file_location, prn=four_chan_id)