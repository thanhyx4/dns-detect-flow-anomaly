#!/usr/bin/python

import anomaly_parser
import gzip
import os
import sys
import time
import xml.dom.minidom
from optparse import OptionParser


class metric_collector:
    """
    Dummy metric collector. Is used as a template for other collectors.
    Every collector must contain a list of text identifiers giving a hint to
    the type of metric being computed.
    """
    metric_decs = ["dummy_metric_0", "dummy_metric_1"]
    def __init__(self):
        sys.stderr.write("Using dummy %s.%s().\n" % (
            self.__class__.__name__, self.__init__.__name__))
        sys.exit(-1)
    def reset(self):
        """ Reset all counters. """
        sys.stderr.write("Using dummy %s.%s().\n" % (
            self.__class__.__name__, self.reset.__name__))
        sys.exit(-1)
    def call(self, xml_dom, anomalous_id):
        """ Performs computation with a given xml_dom object. """
        sys.stderr.write("Using dummy %s.%s().\n" % (
            self.__class__.__name__, self.call.__name__))
        sys.exit(-1)
    def result(self):
        """ Returns the result. """
        sys.stderr.write("Using dummy %s.%s().\n" % (
            self.__class__.__name__, self.result.__name__))
        sys.exit(-1)


A_val_str = "1"
AAAA_val_str = "28"
CERT_val_str = "18"
CNAME_val_str = "5"
DNSKEY_val_str = "48"
DS_val_str = "43"
MX_val_str = "15"
NAPTR_val_str = "35"
NS_val_str = "2"
NSEC_val_str = "47"
NSEC3_val_str = "50"
NSEC3PARAM_val_str = "51"
PTR_val_str = "12"
SOA_val_str = "6"
SPF_val_str = "99"
SRV_val_str = "33"
SSHFP_val_str = "44"
TXT_val_str = "16"
ALL_val_str = "255"


class q_types(metric_collector):
    """ Get ratios of types of queries. """
    metric_desc = [
        "A",     "AAAA",       "CERT",
        "CNAME", "DNSKEY",     "DS",
        "MX",    "NAPTR",      "NS",
        "NSEC",  "NSEC3",      "NSEC3PARAM",
        "PTR",   "SOA",        "SPF",
        "SRV",   "SSHFP",      "TXT",
        "ALL"
        ]
    def __init__(self):
        self.reset()

    def reset(self):
        self.total = 0
        self.A_cnt = 0;     self.AAAA_cnt = 0;       self.CERT_cnt = 0
        self.CNAME_cnt = 0; self.DNSKEY_cnt = 0;     self.DS_cnt = 0
        self.MX_cnt = 0;    self.NAPTR_cnt = 0;      self.NS_cnt = 0
        self.NSEC_cnt = 0;  self.NSEC3_cnt = 0;      self.NSEC3PARAM_cnt = 0
        self.PTR_cnt = 0;   self.SOA_cnt = 0;        self.SPF_cnt = 0
        self.SRV_cnt = 0;   self.SSHFP_cnt = 0;      self.TXT_cnt = 0
        self.ALL_cnt = 0

    def _update_counters(self, val_str, count):
        self.total = self.total + count
        if val_str == A_val_str:
            self.A_cnt = self.A_cnt + count
        elif val_str == AAAA_val_str:
            self.AAAA_cnt = self.AAAA_cnt + count
        elif val_str == CERT_val_str:
            self.CERT_cnt = self.CERT_cnt + count
        elif val_str == CNAME_val_str:
            self.CNAME_cnt = self.CNAME_cnt + count
        elif val_str == DNSKEY_val_str:
            self.DNSKEY_cnt = self.DNSKEY_cnt + count
        elif val_str == DS_val_str:
            self.DS_cnt = self.DS_cnt + count
        elif val_str == MX_val_str:
            self.MX_cnt = self.MX_cnt + count
        elif val_str == NAPTR_val_str:
            self.NAPTR_cnt = self.NAPTR_cnt + count
        elif val_str == NS_val_str:
            self.NS_cnt = self.NS_cnt + count
        elif val_str == NSEC_val_str:
            self.NSEC_cnt = self.NSEC_cnt + count
        elif val_str == NSEC3_val_str:
            self.NSEC3_cnt = self.NSEC3_cnt + count
        elif val_str == NSEC3PARAM_val_str:
            self.NSEC3PARAM_cnt = self.NSEC3PARAM_cnt + count
        elif val_str == PTR_val_str:
            self.PTR_cnt = self.PTR_cnt + count
        elif val_str == SOA_val_str:
            self.SOA_cnt = self.SOA_cnt + count
        elif val_str == SPF_val_str:
            self.SPF_cnt = self.SPF_cnt + count
        elif val_str == SRV_val_str:
            self.SRV_cnt = self.SRV_cnt + count
        elif val_str == SSHFP_val_str:
            self.SSHFP_cnt = self.SSHFP_cnt + count
        elif val_str == TXT_val_str:
            self.TXT_cnt = self.TXT_cnt + count
        elif val_str == ALL_val_str:
            self.ALL_cnt = self.ALL_cnt + count

    def call(self, xml_dom, anomalous_id):
        arrays = xml_dom.getElementsByTagName("array")
        for array in arrays:
            # Search for query types.
            if array.getAttribute("name") == "transport_vs_qtype":
                break
        
        transports = array.getElementsByTagName(
            "data")[0].getElementsByTagName("Transport")
        for transport in transports:
            if transport.getAttribute("val") == "udp":
                for qtype in transport.getElementsByTagName("Qtype"):
                    self._update_counters(qtype.getAttribute("val"),
                        int(qtype.getAttribute("count")))
            elif transport.getAttribute("val") == "tcp":
                for qtype in transport.getElementsByTagName("Qtype"):
                    self._update_counters(qtype.getAttribute("val"),
                        int(qtype.getAttribute("count")))

    def result(self):
        return map (lambda x: "%0.9f" % (float(x) / float(self.total)),
            [
            self.A_cnt,     self.AAAA_cnt,       self.CERT_cnt,
            self.CNAME_cnt, self.DNSKEY_cnt,     self.DS_cnt,
            self.MX_cnt,    self.NAPTR_cnt,      self.NS_cnt,
            self.NSEC_cnt,  self.NSEC3_cnt,      self.NSEC3PARAM_cnt,
            self.PTR_cnt,   self.SOA_cnt,        self.SPF_cnt,
            self.SRV_cnt,   self.SSHFP_cnt,      self.TXT_cnt,
            self.ALL_cnt
            ])


NO_ERR_val_str = "0"
FORM_ERR_val_str = "1"
SERV_FAIL_val_str = "2"
NXDOMAIN_val_str = "3"
NOT_IMP_val_str = "4"
REFUSED_val_str = "5"
YXDOMAIN_val_str = "6"
YXRRSET_val_str = "7"
NXRRSET_val_str = "8"
NOT_AUTH_val_str = "9"
NOT_ZONE_val_str = "10"
BADVERS_SIG_val_str = "16"
BADKEY_val_str = "17"
BADTIME_val_str = "18"
BADMODE_val_str = "19"
BADNAME_val_str = "20"
BADALG_val_str = "21"
BADTRUNC_val_str = "22"

class ip_in_rcode_charts(metric_collector):
    """
    Get ratios of number of relevant XML files where a given IP has been
    listed in rcode charts.
    """
    metric_desc = [
        "NO_ERR_charts",   "FORM_ERR_charts", "SERV_FAIL_charts",
        "NXDOMAIN_charts", "NOT_IMP_charts",  "REFUSED_charts",
        "YXDOMAIN_charts", "YXRRSET_charts",  "NXRRSET_charts",
        "NOT_AUTH_charts", "NOT_ZONE_charts", "BADVERS_SIG_charts",
        "BADKEY_charts",   "BADTIME_charts",  "BADMODE_charts",
        "BADNAME_charts",  "BADALG_charts",   "BADTRUNC_charts"
        ]
    def __init__(self):
        self.reset()

    def reset(self):
        self.files = 0
        self.NO_ERR_cnt = 0;   self.FORM_ERR_cnt = 0; self.SERV_FAIL_cnt = 0
        self.NXDOMAIN_cnt = 0; self.NOT_IMP_cnt = 0;  self.REFUSED_cnt = 0
        self.YXDOMAIN_cnt = 0; self.YXRRSET_cnt = 0;  self.NXRRSET_cnt = 0
        self.NOT_AUTH_cnt = 0; self.NOT_ZONE_cnt = 0; self.BADVERS_SIG_cnt = 0
        self.BADKEY_cnt = 0;   self.BADTIME_cnt = 0;  self.BADMODE_cnt = 0
        self.BADNAME_cnt = 0;  self.BADALG_cnt = 0;   self.BADTRUNC_cnt = 0

    def _update_counters(self, val_str, found):
        if val_str == NO_ERR_val_str:
            self.NO_ERR_cnt = self.NO_ERR_cnt + found
        elif val_str == FORM_ERR_val_str:
            self.FORM_ERR_cnt = self.FORM_ERR_cnt + found
        elif val_str == SERV_FAIL_val_str:
            self.SERV_FAIL_cnt = self.SERV_FAIL_cnt + found
        elif val_str == NXDOMAIN_val_str:
            self.NXDOMAIN_cnt = self.NXDOMAIN_cnt + found
        elif val_str == NOT_IMP_val_str:
            self.NOT_IMP_cnt = self.NOT_IMP_cnt + found
        elif val_str == REFUSED_val_str:
            self.REFUSED_cnt = self.REFUSED_cnt + found
        elif val_str == YXDOMAIN_val_str:
            self.YXDOMAIN_cnt = self.YXDOMAIN_cnt + found
        elif val_str == YXRRSET_val_str:
            self.YXRRSET_cnt = self.YXRRSET_cnt + found
        elif val_str == NXRRSET_val_str:
            self.NXRRSET_cnt = self.NXRRSET_cnt + found
        elif val_str == NOT_AUTH_val_str:
            self.NOT_AUTH_cnt = self.NOT_AUTH_cnt + found
        elif val_str == NOT_ZONE_val_str:
            self.NOT_ZONE_cnt = self.NOT_ZONE_cnt + found
        elif val_str == BADVERS_SIG_val_str:
            self.BADVERS_SIG_cnt = self.BADVERS_SIG_cnt + found
        elif val_str == BADKEY_val_str:
            self.BADKEY_cnt = self.BADKEY_cnt + found
        elif val_str == BADTIME_val_str:
            self.BADTIME_cnt = self.BADTIME_cnt + found
        elif val_str == BADMODE_val_str:
            self.BADMODE_cnt = self.BADMODE_cnt + found
        elif val_str == BADNAME_val_str:
            self.BADNAME_cnt = self.BADNAME_cnt + found
        elif val_str == BADALG_val_str:
            self.BADALG_cnt = self.BADALG_cnt + found
        elif val_str == BADTRUNC_val_str:
            self.BADTRUNC_cnt = self.BADTRUNC_cnt + found

    def call(self, xml_dom, anomalous_id):
        self.files = self.files + 1
        arrays = xml_dom.getElementsByTagName("array")
        for array in arrays:
            # Search for rcode charts.
            if array.getAttribute("name") == "client_addr_vs_rcode":
                break

        rcodes = array.getElementsByTagName(
            "data")[0].getElementsByTagName("Rcode")

        for rcode in rcodes:
            rcode_val = rcode.getAttribute("val")
            client_addrs = rcode.getElementsByTagName("ClientAddr")
            found = 0
            for client_addr in client_addrs:
                if client_addr.getAttribute("val") == anomalous_id:
                    found = 1
                    break

            if found == 1:
                self._update_counters(rcode_val, found)

    def result(self):
        return map(lambda x: "%0.3f" % (float(x) / float(self.files)),
            [
            self.NO_ERR_cnt,   self.FORM_ERR_cnt, self.SERV_FAIL_cnt,
            self.NXDOMAIN_cnt, self.NOT_IMP_cnt,  self.REFUSED_cnt,
            self.YXDOMAIN_cnt, self.YXRRSET_cnt,  self.NXRRSET_cnt,
            self.NOT_AUTH_cnt, self.NOT_ZONE_cnt, self.BADVERS_SIG_cnt,
            self.BADKEY_cnt,   self.BADTIME_cnt,  self.BADMODE_cnt,
            self.BADNAME_cnt,  self.BADALG_cnt,   self.BADTRUNC_cnt
            ])


OK_val_str = "ok"
NON_AUTH_TLD_val_str = "non-auth-tld"

class ip_in_subnet2_charts(metric_collector):
    """
    Get the ratio of relevant XML files where a given IP subnet was listed in
    charts.
    """
    metric_desc = [
        "OK_subnet2", "NON_AUTH_TLD_subnet2"
        ]
    def __init__(self):
        self.reset()

    def reset(self):
        self.files = 0
        self.OK_cnt = 0; self.NON_AUTH_TLD_cnt = 0

    def _update_counters(self, val_str, found):
        if val_str == OK_val_str:
            self.OK_cnt = self.OK_cnt + 1
        elif val_str == NON_AUTH_TLD_val_str:
            self.NON_AUTH_TLD_cnt = self.NON_AUTH_TLD_cnt + 1

    def call(self, xml_dom, anomalous_id):
        self.files = self.files + 1
        arrays = xml_dom.getElementsByTagName("array")
        for array in arrays:
            # Search for client_subnet2 charts.
            if array.getAttribute("name") == "client_subnet2":
                break

        classes = array.getElementsByTagName(
            "data")[0].getElementsByTagName("Class")

        for c in classes:
            class_val = c.getAttribute("val")
            subnet2s = c.getElementsByTagName("ClientSubnet")
            found = 0
            for subnet2 in subnet2s:
                anom_subnet2 = ".".join(anomalous_id.split(".")[0:3]) + ".0"
                if subnet2.getAttribute("val") == anom_subnet2:
                    found = 1
                    break

            if found == 1:
                self._update_counters(class_val, found)

    def result(self):
        return map(lambda x: "%0.3f" % (float(x) / float(self.files)),
            [
            self.OK_cnt, self.NON_AUTH_TLD_cnt
            ])


def get_dsc_xml_file_names(directory_prefix, from_time, to_time):

    """
    Computes the file-names related to the time range.
    The DSC XML files are considered to be stored in the following location:
    dsc_directory_prefix/YYYYMMDD/dscdata/epoch_seconds.dscdata.xml.gz
    where YYYYMMDD is the date which the file has been generated on.
    The XML files contain data collected in one minute intervals, e.g.
    the file 1333238460.dscdata.xml.gz contains traffic information collected
    from 1333238400 to 1333238460 seconds since epoch.
    """

    step = 60
    middle = "dscdata/"
    suffix = ".dscdata.xml.gz"

    file_names = []
    fr = (int(from_time) / step) * step
    to = ((int(to_time) + step - 1) / step) * step

    while fr < to:
        t = time.gmtime(fr)
        file_names.append(directory_prefix +
            "/%04d%02d%02d/" % (t.tm_year, t.tm_mon, t.tm_mday) + middle +
            "%d" % (fr + step) + suffix)
        fr = fr + step
        if not os.path.exists(file_names[-1]):
            sys.stderr.write("Can not find %s\n" % file_names[-1])
            sys.exit(-1)
   
    return file_names


def get_doms_from_xml_gz_file_names(xml_gz_file_names):
    """
    This function opens every given file and converts its content into dom
    trees.
    """
    doms = []

    for xml_gz_file in xml_gz_file_names:
        f = gzip.open(xml_gz_file, "r")
        doms.append(xml.dom.minidom.parse(f))
        f.close()

    return doms


def on_doms_apply(doms, func_obj_list, anomalous_id):
    """
    This function uses the dom trees and applies the metric functions.
    This function is intended to reduce the XML parsing overhead.
    """

    for dom in doms:
        # Applying metrics.
        map(lambda x: x.call(dom, anomalous_id), func_obj_list)

    results = []
    for metric in func_obj_list:
        results = results + metric.result()

    return results


def on_xml_gz_files_apply(xml_gz_file_names, func_obj_list, anomalous_id):
    """
    This function consequently opens the xml_gz_files parses them and calls
    the metric functions. This function is intended to reduce the XML parsing
    overhead.
    """

    for xml_gz_file in xml_gz_file_names:
        # The files have already been tested tor presence in
        # get_dsc_xml_file_names().
        f = gzip.open(xml_gz_file, "r")
        dom = xml.dom.minidom.parse(f)
        f.close()

        # Applying metrics.
        map(lambda x: x.call(dom, anomalous_id), func_obj_list)

    results = []
    for metric in func_obj_list:
        results = results + metric.result()

    return results



parser = OptionParser()
parser.add_option("-a", "--anomalies", dest="anomalies_files",
    action="append", type="string",
    help="Read file containing detected anomalies.",
    metavar="FILE")
parser.add_option("-d", "--dsc_dir_prefix", dest="dsc_directory_prefix",
    action="store", type="string",
    help="Directory prefix pointing to directory containing DSC XML files.",
    metavar="DIRECTORY")
parser.add_option("-s", "--store_file", dest="store_file",
    action="store", type="string",
    help="Store extracted DSC data to FILE.",
    metavar="FILE")

(options, args) = parser.parse_args()

ap = anomaly_parser.anomaly_parser()


if not options.anomalies_files:
    sys.stderr.write("No file containing detected anomalies given.\n")
    sys.exit(-1)


if not options.dsc_directory_prefix:
    sys.stderr.write("No directory prefix to DSC XML files specified.\n")
    sys.exit(-1)
elif not os.path.exists(options.dsc_directory_prefix):
    sys.stderr.write(
        "Error: %s does not exist.\n" % options.dsc_directory_prefix)
    sys.exit(-1)
elif not os.path.isdir(options.dsc_directory_prefix):
    sys.stderr.write(
        "Error: %s is not a directory.\n" % options.dsc_directory_prefix)
    sys.exit(-1)
elif not os.access(options.dsc_directory_prefix, os.R_OK):
    sys.stderr.write("Error: directory %s is not "\
        "readable.\n" % options.dsc_directory_prefix)
    sys.exit(-1)


if not options.store_file:
    sys.stderr.write("No output file specified.\n")
    sys.exit(-1)


# Prepare a list of metrics to be used.
metrics = []
metrics.append(q_types())
metrics.append(ip_in_rcode_charts())
metrics.append(ip_in_subnet2_charts())
result_descriptions = []
for metric in metrics:
    result_descriptions = result_descriptions + metric.metric_desc

try:
    store_file = open(options.store_file, "w")
except:
    sys.stderr.write("Error opening %s\n", options.store_file)
    sys.exit(-1)

store_file.write("# <From: > <To: > <IP: > %s\n" % " ".join(result_descriptions))


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

        # Get list of anomaly related DSC files.
        dsc_xml_files = get_dsc_xml_file_names(options.dsc_directory_prefix,
            anomalies.from_time, anomalies.to_time)

        doms = get_doms_from_xml_gz_file_names(dsc_xml_files)

        for ip in anomalies.anomalies:
            # Reset all counters.
            map(lambda x: x.reset(), metrics)

            # Apply metrics for given IP
#            results = on_xml_gz_files_apply(dsc_xml_files, metrics, ip)
            results = on_doms_apply(doms, metrics, ip)

            # Print results for given IP
            store_file.write("<From: %s> <To: %s> <IP: %s> %s\n" % (
                anomaly_parser.anomaly_parser.file_format_from_since_epoch(
                    anomalies.from_time),
                anomaly_parser.anomaly_parser.file_format_from_since_epoch(
                    anomalies.to_time),
                ip, " ".join(results)))

        # Free dom trees.
        map(lambda x: x.unlink(), doms)

        try:
            anomalies = ap.get_next_anomalies()
        except parser_error as e:
            sys.stderr.write("Error while parsing file %s: "\
                "%s\n" % (anomf, e.value))
            sys.exit(-1)

    ap.close_file()

store_file.close()
