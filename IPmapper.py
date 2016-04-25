from SH_Sniffer import getPacketsFromFile, make_map, writeMapToFile

if __name__ == "__main__":
    pkts = getPacketsFromFile()
    doc = make_map(pkts)
    filename = "map.html"
    writeMapToFile(filename, doc)
