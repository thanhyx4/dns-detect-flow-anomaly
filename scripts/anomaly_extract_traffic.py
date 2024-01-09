#!/usr/bin/python

import anomaly_parser
import os
import subprocess
import sys
import re
from optparse import OptionParser

ipv4addr_re = re.compile("([0-9]+\.){3}[0-9]+")

extracted_values = ["frame.time",
    "ip.src", "ipv6.src", "udp.srcport", #"ip.src_host", "ip.geoip.src_country",
    "ip.dst", "ipv6.dst", "udp.dstport", #"ip.dst_host", "ip.geoip.dst_country",
    "dns.id", "dns.qry.class", "dns.qry.type", "dns.qry.name",
    "dns.resp.ttl", "dns.resp.type",
    "dns.flags", "dns.flags.rcode"]
extract_cmd = reduce(lambda x, y: x + ["-e", y], [[]] + extracted_values)


def store_traffic_from_files(ip, files, begin_time, end_time,
                             output=sys.stdout, interactive=False,
                             IPv4=False, IPv6=False):
    """Prints traffic regarding the desired ip address."""
    if IPv4:
        read_filter = "ip.addr == " + ip
    elif IPv6:
        read_filter = "ipv6.addr == " + ip
    else:
        sys.stderr.write("No ip address specified.\n")
        sys.exit(-1)

    for fname in files:
        cmd = ["tshark", "-r", fname,
               "-o", "name_resolve:mnt", "-o", "ip.use_geoip:TRUE",
               "-R", read_filter, 
               #"-t", "a",
               "-T", "fields", "-E", "separator=,"] + extract_cmd
        output.write("# "+ ", ".join(extracted_values) + "\n")
        output.flush()
        p = subprocess.Popen(cmd, stdout=output)
        p.wait()
        if interactive:
            raw_input("Press enter for next...")


parser = OptionParser()
parser.add_option("-a", "--anomalies", dest="anomalies_files",
    action="append", type="string",
    help="Read file containing detected anomalies.",
    metavar="FILE")
parser.add_option("-s", "--store_dir", dest="store_directory",
    action="store", type="string",
    help="Store extracted anomaly files into directory.",
    metavar="DIRECTORY")

(options, args) = parser.parse_args()

ap = anomaly_parser.anomaly_parser()


if not options.anomalies_files:
    sys.stderr.write("No file containing detected anomalies given.\n")
    sys.exit(-1)


if options.store_directory:
    if not os.path.exists(options.store_directory):
        os.makedirs(options.store_directory)
    elif not os.path.isdir(options.store_directory):
        sys.stderr.write(
            "Error: %s is not a directory.\n" % options.store_directory)
        sys.exit(-1)
    elif not os.access(options.store_directory, os.W_OK):
        sys.stderr.write("Error: directory %s is not "\
            "writeable.\n" % options.store_directory)
        sys.exit(-1)
    


for anomf in options.anomalies_files:
    try :
        ap.open_file(anomf)
    except:
        sys.stderr.write("Cannot open file %s\n" % anomf)
        continue

    detection_settings = None
    try:
        detection_settings = ap.get_detection_settings()
    except parser_error as e:
        sys.stderr.write("Error while parsing detection settings from "\
            "file %s\n" % anomf)
        sys.exit(-1)

    # read through the anomalies
    anomalies = None
    try:
        anomalies = ap.get_next_anomalies()
    except parser_error as e:
        sys.stderr.write("Error while parsing file %s: %s\n" % (anomf, e.value))
        sys.exit(-1)
    while anomalies:

        file_names = detection_settings.get_pcap_file_names(
            anomaly_parser.get_pcap_date_range(anomalies.from_time,
                anomalies.to_time))

        for ip in anomalies.anomalies:

            IPv4 = ipv4addr_re.match(ip) != None
            IPv6 = (":" in ip) and (re.search("(([a-zA-Z])|-)+", ip) == None)
            if (IPv4 == IPv6):
                sys.stderr.write("Could not determine type of %s\n" % ip)
                sys.exit(-1)

            if options.store_directory:
                summary_file = None
                summary_path = options.store_directory + "/" + ip + "-" +\
                anomaly_parser.get_pcap_date_suffix(anomalies.from_time) + "-" +\
                anomaly_parser.get_pcap_date_suffix(anomalies.to_time) +\
                "-traffic_summary.txt"
                print summary_path
                try:
                    summary_file = open(summary_path, "w")
                except:
                    sys.stderr.write("Error creating file %s\n" % summary_path)
                    sys.exit(-1)

                store_traffic_from_files(ip, file_names, anomalies.from_time,
                    anomalies.to_time, output=summary_file, IPv4=IPv4, IPv6=IPv6)

                summary_file.close()

            else:
                store_traffic_from_files(ip, file_names, anomalies.from_time,
                    anomalies.to_time, interactive=True, IPv4=IPv4, IPv6=IPv6)

        try:
            anomalies = ap.get_next_anomalies()
        except parser_error as e:
            sys.stderr.write("Error while parsing file %s: "\
                "%s\n" % (anomf, e.value))
            sys.exit(-1)

    ap.close_file()
