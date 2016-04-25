from SH_Sniffer import getPacketsFromFile, getPacketsInfo, graphPacketsInfo

if __name__ == "__main__":
    pkts = getPacketsFromFile()
    browsers, oses, devices, activity_map, first_date = getPacketsInfo(pkts)
    graphPacketsInfo(browsers, oses, devices, activity_map, first_date)
