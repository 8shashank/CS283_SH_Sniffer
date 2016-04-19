# load the pcap file
from scapy.all import *
from user_agents import parse
import re

pkts = rdpcap("httpdata.pcap")

# web_browsers and their counts
web_browsers = {}

# operating systems and their counts
oses = {}

# devices and their count
devices = {}

# print pkts[0].load.split('\r\n')[5]

ua_pattern = re.compile('User-Agent:(.*?)\\r\\n')

for pkt in pkts:
    ua_object = ua_pattern.search(pkt.load)
    if ua_object:
        user_agent = parse(ua_object.group())
        browser_family = user_agent.browser.family
        os = user_agent.os.family
        device = user_agent.device.family
        if browser_family in web_browsers:
            web_browsers[browser_family] += 1
        else:
            web_browsers[browser_family] = 1
        if os in oses:
            oses[os] += 1
        else:
            oses[os] = 1
        if device in devices:
            devices[device] += 1
        else:
            devices[device] = 1

print web_browsers
print oses
print devices
