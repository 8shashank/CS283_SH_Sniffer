# load the pcap file
from scapy.all import *

pkts = rdpcap("httpdata.pcap")
print pkts[0].load.split('\r\n')
