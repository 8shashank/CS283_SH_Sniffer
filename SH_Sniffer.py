# load the pcap file
from scapy.all import *
from user_agents import parse
import re

pkts = rdpcap("httpdata.pcap")

web_browsers = {}
# print pkts[0].load.split('\r\n')[5]

str_pattern = re.compile('User-Agent:(.*?)\\r\\n')
for pkt in pkts:
    match_object = str_pattern.search(pkt.load)
    if match_object:
        browser_family = parse(match_object.group()).browser.family
        if browser_family in web_browsers:
            web_browsers[browser_family] += 1
        else:
            web_browsers[browser_family] = 1

print web_browsers
