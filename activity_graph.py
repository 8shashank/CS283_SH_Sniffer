from datetime import datetime
from scapy.all import *
from collections import OrderedDict
from bokeh.plotting import figure, output_file, show

pkts=rdpcap("httpdata.pcap")

first_date=datetime.fromtimestamp(int(pkts[0].time))

activity_map=OrderedDict()
for pkt in pkts:
	time=datetime.fromtimestamp(int(pkt.time))
	if time in activity_map:
		activity_map[time]+=1
	else:
		activity_map[time]=1

x=[(time-first_date).total_seconds() for time in activity_map.keys()]
y=activity_map.values()

output_file("square.html")
p=figure(plot_width=1600, plot_height=400)
p.title="Network activity over time"
p.xaxis.axis_label="Time in seconds"
p.yaxis.axis_label="Number of packets"
p.line(x,y)
show(p)
