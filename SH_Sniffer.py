from __future__ import division
from scapy.all import *
from user_agents import parse
from collections import defaultdict, OrderedDict, Counter
from datetime import datetime
from IPy import IP
import urllib2
import json
import random
import itertools
import sys
import re
from bokeh.util.browser import view
from bokeh.document import Document
from bokeh.embed import file_html
from bokeh.models.glyphs import Circle
from bokeh.models import (
    GMapPlot, Range1d, ColumnDataSource, PanTool, HoverTool, WheelZoomTool, BoxSelectTool, GMapOptions)
from bokeh.resources import INLINE
from bokeh.charts import Bar, output_file, show, vplot
from bokeh.plotting import figure

def getPacketsFromFile(fileName="httpdata.pcap"):
    return rdpcap("httpdata.pcap")

'''
The following methods are for packet information
graphing purpose
'''
def getPacketsInfo(pkts):
    # web_browsers and their counts
    web_browsers = defaultdict(int)

    # operating systems and their counts
    oses = defaultdict(int)

    # devices and their count
    devices = defaultdict(int)

    # print pkts[0].load.split('\r\n')[5]

    ua_pattern = re.compile('User-Agent:(.*?)\\r\\n')

    activity_map = OrderedDict()

    first_date = datetime.fromtimestamp(int(pkts[0].time))

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

        time = datetime.fromtimestamp(int(pkt.time))

        if time in activity_map:
            activity_map[time]+=1
        else:
            activity_map[time]=1

    # Uncomment this to see the details of the packets
    # print web_browsers
    # print oses
    # print devices
    return (web_browsers, oses, devices, activity_map, first_date)

def graphPacketsInfo(web_browsers, oses, devices, activity_map, first_date):
    browser_data={"x":web_browsers.keys(), "y": web_browsers.values()}
    os_data={"x":oses.keys(), "y":oses.values()}
    devices_data={"x":devices.keys(), "y":devices.values()}

    output_file("browsers.html", title="Browser distribution")
    browser_chart=Bar(browser_data, width=600, height=600, label="x",values="y",
                      xlabel="Browser", ylabel="Count", title="Browser distribution")

    os_chart = Bar(os_data, width=600,height=600, label="x", values="y",
                   xlabel="OS", ylabel="Count", title="OS distribution")

    devices_chart = Bar(devices_data, width=600, height=600, label="x", values="y",
                        xlabel="Device", ylabel="Count", title="Device distribution")

    activity_chart = figure(plot_width=1600, plot_height=400, title="Network activity over time")
    activity_chart.xaxis.axis_label = "Time in seconds"
    activity_chart.yaxis.axis_label = "Number of packets"
    activity_x = [(time-first_date).total_seconds() for time in activity_map.keys()]
    activity_y = activity_map.values()
    activity_chart.line(activity_x,activity_y)

    show(vplot(browser_chart, os_chart, devices_chart, activity_chart))


'''
The following methods are for IP mapping purpose
'''

# Returns a list of random N colors
# Source:
# https://stackoverflow.com/questions/876853/generating-color-ranges-in-python
def get_n_colors(N):
    colors = []
    for i in range(0, N):
        colors.append("#%03x" % random.randint(0, 0xFFF))
    return colors

# Like range(a,b,step) but for float values
# Source:
# https://stackoverflow.com/questions/477486/python-decimal-range-step-value
def frange(x, y, jump):
    while x < y:
        yield x
        x += jump

# Returns tuple containing lists of latitude, longitude and hosting org.
# Side effect: Removes IP from input parameters if it is invalid
def reverse_lookup_ips(top_ips, top_counts):
    lat = []
    lon = []
    org = []
    # Get the latitude, longitude data for top IPs
    for ip in top_ips:
        response = urllib2.urlopen("http://ip-api.com/json/" + ip).read()
        data = json.loads(response)

        if data["status"] == "success":
            lat.append(data["lat"])
            lon.append(data["lon"])
            org.append(data["org"] if "org" in data else "N/A")

        # if failed, remove IP address from list of IPs to plot
        else:
            idx = top_ips.index(ip)
            top_ips.remove(idx)
            top_counts.remove(idx)
            print "Could not geolocate ip " + ip
    return (lat, lon, org)

# Fuzz locations by a bit so they're not all centered at one point
# Call if API returns same lat, lon for any location in a particular city
def fuzz_locations(lats, lons):
    # just in case two lists are of different size, use smaller
    FUZZ_FACTOR = 0.03
    smaller_len = len(lats) if len(lats) < len(lons) else len(lons)
    for i in range(0, smaller_len):
        lats[i] += (FUZZ_FACTOR * random.random())
        lons[i] += (FUZZ_FACTOR * random.random())
    return (lats, lons)

# returns if IP is public, private, reserved, or in error case invalid.
# all uppercase return values.
def get_ip_type(ip):
    try:
        return IP(ip).iptype()
    except Exception, e:
        print e
        return "INVALID"

# Create the main map document and return it
def make_map(pkts):
    NUMBER_OF_COORDINATES = 30  # How many IPs to plot

    ipdict = defaultdict(int)

    # Count all IP addresses in capture file
    for pkt in pkts:
        ipdict[pkt.src] += 1
        ipdict[pkt.dst] += 1

    # Filter out the private/local IPs
    publicips = {
        ip: count for (ip, count) in ipdict.iteritems() if get_ip_type(ip) == 'PUBLIC'}

    if not publicips:
        print "Could not find any parseable public IPs. Exiting.."
        return Document()

    # Get the top 30 public IPs that occur the most often
    top_items = Counter(publicips).most_common(NUMBER_OF_COORDINATES)
    top_ips = [ip for ip, count in top_items]
    top_counts = [publicips[ip] for ip in top_ips]

    # Scale the counts so that maximum circle size is 100px
    sizes = [100 * count // top_counts[0] for count in top_counts]

    # Get random colors for circles
    colors = get_n_colors(NUMBER_OF_COORDINATES)

    # Get lists of latitude and longitude for IPs.
    lat, lon, org = reverse_lookup_ips(top_ips, top_counts)
    lat, lon = fuzz_locations(lat, lon)

    # Drawing logic starts here
    centerx, centery = lat[0], lon[0]
    # JSON style string taken from: https://snazzymaps.com/style/1/pale-dawn
    map_options = GMapOptions(lat=centerx, lng=centery, map_type="satellite", zoom=5, styles="""
    [{"featureType":"administrative","elementType":"all","stylers":[{"visibility":"on"},{"lightness":33}]},{"featureType":"landscape","elementType":"all","stylers":[{"color":"#f2e5d4"}]},{"featureType":"poi.park","elementType":"geometry","stylers":[{"color":"#c5dac6"}]},{"featureType":"poi.park","elementType":"labels","stylers":[{"visibility":"on"},{"lightness":20}]},{"featureType":"road","elementType":"all","stylers":[{"lightness":20}]},{"featureType":"road.highway","elementType":"geometry","stylers":[{"color":"#c5c6c6"}]},{"featureType":"road.arterial","elementType":"geometry","stylers":[{"color":"#e4d7c6"}]},{"featureType":"road.local","elementType":"geometry","stylers":[{"color":"#fbfaf7"}]},{"featureType":"water","elementType":"all","stylers":[{"visibility":"on"},{"color":"#acbcc9"}]}]
    """)

    x_range = Range1d()
    y_range = Range1d()

    plot = GMapPlot(
        x_range=x_range, y_range=y_range,
        map_options=map_options,
        title="Top public IP addresses",
        plot_width=1000
    )

    source = ColumnDataSource(
        data=dict(
            lat=lat,
            lon=lon,
            fill=colors,
            ip=top_ips,
            count=top_counts,
            organization=org,
            size=sizes,
            rank=range(1, len(top_ips) + 1),
            # Circles become more opaque as you go from largest to smallest
            opacity=list(frange(0.1, 0.9, (0.9 - 0.1) / len(top_ips)))
        )
    )

    circle = Circle(x="lon", y="lat", size="size",
                    fill_color="fill", fill_alpha=0.7, line_color="black")
    plot.add_glyph(source, circle)

    # Adds the ability to see IP address, location, index on hover
    hover = HoverTool(
        tooltips=[
            ("Rank", "@rank"),
            ("IP address", "@ip"),
            ("Packet count", "@count"),
            ("Hosted by", "@organization"),
            ("Location", "(@lat, @lon)")
        ],
        # not sure if I prefer follow_mouse or snap_to_data
        # point_policy="snap_to_data"
    )

    # add tools to pan, zoom and hover to plot
    plot.add_tools(PanTool(), WheelZoomTool(), hover)

    doc = Document()
    doc.add_root(plot)
    return doc

def writeMapToFile(filename, doc):
    with open(filename, "w") as f:
        f.write(file_html(doc, INLINE, "Google Maps Example"))
    print "Wrote %s" % filename
    view(filename)

