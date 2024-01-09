#!/usr/bin/python

import anomaly_parser
import os
import re
import subprocess
import sys
import time
from optparse import OptionParser


ipv4addr_re = re.compile("([0-9]+\.){3}[0-9]+")


# Do not change the order of the list, only append new possibilities.
anomaly_classes = ["Unknown",         # Also unclassified
                   "Suspicious",
                   "Resolver",
                   "Broken_resolver",
                   "Web_crawler",
                   "Blind_enumeration",
                   "Informed_enumeration",
                   "Short_TTL",
                   "Querying_MX"]
unclassified_id = 0

"<From: %s> <To: %s> <IP: %s> <Anomaly_type: %s>"
from_re = re.compile("<From: [^>]+>")
to_re = re.compile("<To: [^>]+>")
ip_re = re.compile("<IP: [^>]+>")
anom_re = re.compile("<Anomaly_type: [^>]+>")


class anomaly_descriptor:
    total_cntr = None
    last_choice = None
    def __init__(self):
        self.total_cntr = 0
        self.last_choice_id = 0
    def __str__(self):
        return "%s(total_cntr=%r, last_choice_id=%r)" % (
            self.__class__.__name__, self.total_cntr, self.last_choice_id)


class struct_classified_anomaly:
    from_time = None
    to_time = None
    ip = None
    class_id = None
    def __init__(self, from_time=None, to_time=None, ip=None, class_id=None):
        self.from_time = from_time
        self.to_time = to_time
        self.ip = ip
        self.class_id = class_id
    def __str__(self):
        return "%s(from_type=%r, to_type=%r, ip=%r, class_id=%r)" %(
            self.__class__.__name__,
            self.from_time, self.to_time, self.ip, self.class_id)



class manual_anomaly_classifier:
    menu_str = None
    origin_cntr = None
    cf = None
    cf_line_begin = None
    cf_line_end = None

    def __init__(self):
        self.menu_str = []
        for t in anomaly_classes:
            self.menu_str.append(str(len(self.menu_str)) + ") " + t)
        self.menu_str = "\n".join(self.menu_str)
        self.origin_cntr = {}
        self.cf = None

    def _user_input_id(self, default_id):
        read = None
        while read == None:
            read = raw_input("Your opinion? [%d]:" % default_id)
            if read == "":
                read = default_id
                continue
            try:
                read = int(read)
            except:
                read = None
                continue
            if (read < 0) or (read >= len(anomaly_classes)):
                read = None
        return read

    def _interactive_menu(self, ip):
        if not ip in self.origin_cntr.keys():
            self.origin_cntr[ip] = anomaly_descriptor()
        print self.menu_str
        self.origin_cntr[ip].last_choice_id = \
            self._user_input_id(self.origin_cntr[ip].last_choice_id)
        return self.origin_cntr[ip].last_choice_id

    def _write_line(self, from_time, to_time, ip, type_id):
        self.cf.write("<From: %s> <To: %s> <IP: %s> <Anomaly_type: %s>\n" % (
            anomaly_parser.anomaly_parser.file_format_from_since_epoch(from_time),
            anomaly_parser.anomaly_parser.file_format_from_since_epoch(to_time),
            ip, type_id))

    def _parse_line(self, line, from_time, to_time, ip):
        f = from_re.search(line)
        t = to_re.search(line)
        i = ip_re.search(line)
        a = anom_re.search(line)
        if (not f) or (not t) or (not i) or (not a):
            sys.stderr.write("Error parsing classification file.\n")
            sus.exit(-1)
        # Get rid of the parentheses and perform conversion.
        f = re.sub("<[^:]+: ", "", f.group(0))[:-1]
        f = anomaly_parser.anomaly_parser.since_epoch_from_file_format(f)
        t = re.sub("<[^:]+: ", "", t.group(0))[:-1]
        t = anomaly_parser.anomaly_parser.since_epoch_from_file_format(t)
        i = re.sub("<[^:]+: ", "", i.group(0))[:-1]
        a = re.sub("<[^:]+: ", "", a.group(0))[:-1]
        try:
            a = int(a)
        except:
            sys.stderr.write("Invalid conversion of anomaly class.\n")
            sys.exit(-1)

        if (f != from_time) or (t != to_time) or (i != ip):
            sys.stderr.write("Classified line does not match current anomaly.\n")
            sys.exit(-1)

        return struct_classified_anomaly(
            from_time=f, to_time=t, ip=i, class_id=a)

    def open_file(self, filename):
        self.cf = open(filename, "r+")
        self.cf_line_begin = self.cf.tell()
        self.cf_line_end = self.cf.tell()

    def close_file(self):
        self.cf.close()

    def classify_anomaly(self, from_time, to_time, ip):
        if not ip in self.origin_cntr.keys():
            self.origin_cntr[ip] = anomaly_descriptor()

        self.cf_line_begin = self.cf.tell()
        line = self.cf.readline()
        self.cf_line_end = self.cf.tell()
        if self.cf_line_begin != self.cf_line_end:
            read_classification = self._parse_line(
                line, from_time, to_time, ip)
            print "<<< Reading classification"
            print line,
            if (read_classification.class_id != unclassified_id):
                print "<<< Skipping because already classified"
                return
            read_classification.class_id = self._interactive_menu(
                read_classification.ip)
            if (read_classification.class_id == unclassified_id):
                # Skip because nothing changed.
                return
            # Store rest of file.
            rest_of_file = self.cf.readlines()
            # Seek begin line.
            self.cf.seek(self.cf_line_begin)
            # Write line.
            self._write_line(
                read_classification.from_time, read_classification.to_time,
                read_classification.ip, read_classification.class_id)
            # Store position.
            self.cf_line_end = self.cf.tell()
            # Write rest of file.
            for line in rest_of_file:
                self.cf.write(line)
            # Restore position.
            self.cf.seek(self.cf_line_end)
            self.cf.flush()
        else:
            # Only classify and write to output file
            self._write_line(from_time, to_time, ip,
                self._interactive_menu(ip))
            self.cf.flush()



parser = OptionParser()
parser.add_option("-a", "--anomalies", dest="anomalies_file",
    action="store", type="string",
    help="Read file containing detected anomalies.",
    metavar="FILE")
parser.add_option("-r", "--read_dir", dest="read_directory",
    action="store", type="string",
    help="Read extracted anomaly files from directory.",
    metavar="DIRECTORY")
parser.add_option("-c", "--classification", dest="classification_file",
    action="store", type="string",
    help="Read/write corresponding classification file.",
    metavar="FILE")

(options, args) = parser.parse_args()

ap = anomaly_parser.anomaly_parser()
mac = manual_anomaly_classifier()


if not options.anomalies_file:
    sys.stderr.write("No file containing detected anomalies given.\n")
    sys.exit(-1)


if not options.read_directory:
    sys.stderr.write("No directory containing extracted anomalies given.\n")
    sys.exit(-1)
elif not os.path.exists(options.read_directory):
    sys.stderr.write("Error: %s does not exist.\n" % options.read_directory)
    sys.exit(-1)
elif not os.path.isdir(options.read_directory):
    sys.stderr.write(
        "Error: %s is not a directory.\n" % options.read_directory)
    sys.exit(-1)
elif not os.access(options.read_directory, os.R_OK):
    sys.stderr.write("Error: directory %s is not "\
        "readable.\n" % options.read_directory)
    sys.exit(-1)

if not options.classification_file:
    sys.stderr.write("No classification file specified.\n")
    sys.exit(-1)
if not os.path.exists(options.classification_file):
    try :
        f = open(options.classification_file, "w")
    except:
        sys.stderr.write("Cannot create file %s\n" % options.classification_file)
        sys.exit(-1)
    f.close()
    del f


anomf = options.anomalies_file

try:
    ap.open_file(anomf)
except:
    sys.stderr.write("Cannot open file %s\n" % anomf)
    sys.exit(-1)

try:
    mac.open_file(options.classification_file)
except:
    sys.stderr.write("Cannot open file %s\n" % options.classification_file)
    sys.exit(-1)
    

detection_settings = None
try:
    detection_settings = ap.get_detection_settings()
except parser_error as e:
    sys.stderr.write("Error while parsing detection settings from "\
        "file %s\n" % anomf)
    sys.exit(-1)

# Read through the anomalies.
anomalies = None
try:
    anomalies = ap.get_next_anomalies()
except parser_error as e:
    sys.stderr.write("Error while parsing file %s: %s\n" % (anomf, e.value))
    sys.exit(-1)

while anomalies:

    for ip in anomalies.anomalies:

        IPv4 = ipv4addr_re.match(ip) != None
        IPv6 = (":" in ip) and (re.search("(([a-zA-Z])|-)+", ip) == None)
        if (IPv4 == IPv6):
            sys.stderr.write("Could not determine type of %s\n" % ip)
            sys.exit(-1)

        summary_file = None
        summary_path = options.read_directory + "/" + ip + "-" +\
        anomaly_parser.get_pcap_date_suffix(anomalies.from_time) + "-" +\
        anomaly_parser.get_pcap_date_suffix(anomalies.to_time) +\
        "-traffic_summary.txt"
        if (not os.path.exists(summary_path)) or\
           (not os.access(summary_path, os.R_OK)):
            sys.stderr.write("Cannot find %s.\n" % summary_path)
            continue

        cmd = ["xterm", "-geometry", "200x50",
               "-e", "less <" + summary_path]
        p = subprocess.Popen(cmd)

#        cmd = ["nslookup", ip]
#        subprocess.call(cmd)

        mac.classify_anomaly(anomalies.from_time, anomalies.to_time, ip)

        # Force terminal exit.
        p.terminate()
        p.wait()

    try:
        anomalies = ap.get_next_anomalies()
    except parser_error as e:
        sys.stderr.write("Error while parsing file %s: "\
            "%s\n" % (anomf, e.value))
        sys.exit(-1)

ap.close_file()
