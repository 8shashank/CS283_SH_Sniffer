# load the pcap file
from scapy.all import *
from user_agents import parse
from collections import defaultdict, OrderedDict
from bokeh.charts import Bar, output_file, show, vplot
from bokeh.plotting import figure
from datetime import datetime
import re

pkts = rdpcap("httpdata.pcap")

# web_browsers and their counts
web_browsers = defaultdict(int)

# operating systems and their counts
oses = defaultdict(int)

# devices and their count
devices = defaultdict(int)

# print pkts[0].load.split('\r\n')[5]

ua_pattern = re.compile('User-Agent:(.*?)\\r\\n')


activity_map=OrderedDict()
first_date=datetime.fromtimestamp(int(pkts[0].time))

for pkt in pkts:
    ua_object = ua_pattern.search(pkt.load)
    if ua_object:
        user_agent = parse(ua_object.group())
        browser_family = user_agent.browser.family
        web_browsers[browser_family] += 1
        os = user_agent.os.family
        oses[os] += 1
        device = user_agent.device.family
        devices[device] += 1

    time=datetime.fromtimestamp(int(pkt.time))
    if time in activity_map:
        activity_map[time]+=1
    else:
        activity_map[time]=1

print web_browsers
print oses
print devices

browser_data={"x":web_browsers.keys(), "y": web_browsers.values()}
os_data={"x":oses.keys(), "y":oses.values()}
devices_data={"x":devices.keys(), "y":devices.values()}

output_file("browsers.html", title="Browser distribution")
browser_chart=Bar(browser_data, width=600, height=600, label="x",values="y",
 xlabel="Browser", ylabel="Count", title="Browser distribution")
os_chart=Bar(os_data, width=600,height=600, label="x", values="y",
xlabel="OS", ylabel="Count", title="OS distribution")

devices_chart=Bar(devices_data, width=600, height=600, label="x", values="y",xlabel="Device", ylabel="Count", title="Device distribution")

activity_chart=figure(plot_width=1600, plot_height=400, title="Network activity over time")
activity_chart.xaxis.axis_label="Time in seconds"
activity_chart.yaxis.axis_label="Number of packets"
activity_x=[(time-first_date).total_seconds() for time in activity_map.keys()]
activity_y=activity_map.values()
activity_chart.line(activity_x,activity_y)

show(vplot(browser_chart, os_chart, devices_chart, activity_chart))