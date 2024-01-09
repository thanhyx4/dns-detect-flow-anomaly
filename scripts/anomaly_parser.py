#!/usr/bin/python

import glob
import re
import sys
import time

class parser_error(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class struct_settings:
    pcap_dir = None
    file_name_prefix = None
    file_names = None

    def __init__(self, pcap_dir=None, file_name_prefix=None,
                 file_names=None):
        self.pcap_dir = pcap_dir
        self.file_name_prefix = file_name_prefix
        self.file_names = file_names

    def __str__(self):
        return "%s(pcap_dir=%r, file_name_prefix=%r, file_names=%r)" % (
            self.__class__.__name__,
            self.pcap_dir, self.file_name_prefix, self.file_names)

    def _get_full_name_from_wildcard(self, file_wildcard):
        files = glob.glob(file_wildcard+"*") # wild-card search
        if len(files) != 1:
            sys.stderr.write("File wild-card %s is either ambiguous or "\
                "wrong.\n" % file_wildcard+"*")
            sys.exit(-1)
        else:
            return files[0]

    def get_pcap_file_names(self, date_suffixes):
        """Returns a list of pcap files containing required traffic."""
        files = map(lambda x: self._get_full_name_from_wildcard(
            self.pcap_dir+self.file_name_prefix+x+"*"), date_suffixes)
        return files


class struct_anomalies:
    from_time = None
    to_time = None
    cnt_found = None
    cnt_all = None
    anomalies = None
    def __init__(self, from_time=None, to_time=None, cnt_found=None,
                 cnt_all=None, anomalies=None):
        self.from_time = from_time
        self.to_time = to_time
        self.cnt_found = cnt_found
        self.cnt_all = cnt_all
        self.anomalies = anomalies
    def __str__(self):
        return "%s(from_time=%r, to_time=%r, cnt_found=%r, cnt_all=%r, "\
            "anomalies=%r)" % (
            self.__class__.__name__,
            self.from_time, self.to_time, self.cnt_found, self.cnt_all,
            self.anomalies)


class anomaly_parser:
    def __init__(self):
        self.mergecap_re = re.compile("#mergecap ")
        self.from_re = re.compile("From: ")
        self.to_re = re.compile("To: ")
        self.found_re = re.compile("found anomalies ")
        self.ok_re = re.compile("ok")

        self.st_expect_from_or_ok = 0
        self.st_expect_to = 1
        self.st_expect_found = 2

        self.af = None
        self.first_line = None
        self.state = self.st_expect_from_or_ok

        self.cntr_line = 0

    def open_file(self, filename):
        self.first_line = None
        self.af = open(filename, "r")
        self.first_line = self.af.readline()
        self.state = self.st_expect_from_or_ok
        self.cntr_line = 1

    def close_file(self):
        self.af.close()
        self.first_line = None

    @staticmethod
    def since_epoch_from_file_format(string_time):
        return time.mktime(time.strptime(string_time, "%a %b %d %H:%M:%S %Y"))

    @staticmethod
    def file_format_from_since_epoch(since_epoch):
        return time.strftime("%a %b %d %H:%M:%S %Y",
                             time.localtime(since_epoch))

    def _parse_first_line(self, line):
        if not self.mergecap_re.search(line):
            return None
        cmd = self.mergecap_re.sub("", line.strip())
        files = re.sub(" -w - \\| .*", "", cmd)
        if len(files.split(" ")) > 1 :
            sys.stderr.write("Multiple pcap files -- currently unsupported.\n")
            sys.exit(-1)
        # assume one wild-card file name
        pcap_dir = re.sub("[^/]*$", "", files)
        file_name_prefix = re.sub("^.*[/]", "", files)
        file_name_prefix = re.sub("[0-9]+\..*$", "", file_name_prefix)
        return (pcap_dir, file_name_prefix, None)

    def _parse_from_line(self, line):
        if not self.from_re.search(line):
            return None
        return self.since_epoch_from_file_format(
            self.from_re.sub("", line.strip()))

    def _parse_to_line(self, line):
        if not self.to_re.search(line):
            return None
        return self.since_epoch_from_file_format(
            self.to_re.sub("", line.strip()))

    def _parse_found_line(self, line):
        if not self.found_re.search(line):
            return None
        data = re.split(" : ", self.found_re.sub("", line.strip()))
        num = re.findall("[0-9]+", data[0])
        num_found = int(num[0])
        num_all = int(num[1])
        data = re.split(", ", data[1].strip())
        return (num_found, num_all, data)

    def get_detection_settings(self):
        settings = self._parse_first_line(self.first_line)
        if settings:
            return struct_settings(settings[0], settings[1], settings[2])
        else:
            raise parser_error("Error parsing settings line.")

    def get_next_anomalies(self):
        """
        Returns structure containing, start time, stop time and 
        detected anomalies.
        """

        from_time = None
        to_time = None
        found_anomalies = None

        line = self.af.readline()
        self.cntr_line = self.cntr_line + 1
        while line:
            if self.state == self.st_expect_from_or_ok:
                from_time = self._parse_from_line(line)
                if from_time:
                    self.state = self.st_expect_to
                elif self.ok_re.search(line):
                    return None
                else:
                    raise parser_error("Error parsing \"From\" value "\
                        "at line %d" % self.cntr_line)

            elif self.state == self.st_expect_to:
                to_time = self._parse_to_line(line)
                if to_time:
                    self.state = self.st_expect_found
                else:
                    raise parser_error("Error parsing \"To\" value "\
                        "at line %d" % self.cntr_line)

            elif self.state == self.st_expect_found:
                found_anomalies = self._parse_found_line(line)
                if found_anomalies:
                    self.state = self.st_expect_from_or_ok
                    return struct_anomalies(from_time, to_time,
                        found_anomalies[0], found_anomalies[1],
                        found_anomalies[2])
                else:
                    raise parser_error("Error parsing \"found anomalies\" "\
                        "at line %d" % self.cntr_line)

            line = self.af.readline()
            self.cntr_line = self.cntr_line + 1

        return None


def get_pcap_date_suffix(epoch_secs):
    gt = time.gmtime(epoch_secs)
    return "%04d%02d%02d.%02d%02d%02d" % (
        gt.tm_year, gt.tm_mon, gt.tm_mday,
        gt.tm_hour, (gt.tm_min / 10) * 10, 0)


def get_pcap_date_range(from_secs, to_secs):
    """
    Computes a list of file suffixes to identify files to search for traffic.

    from_secs:   Seconds since epoch identifying start.
    to_secs:     Seconds since epoch identifying end.

    Returns a list containing suffixes identifying pcap files in format
    YYYYMMDD.HHMMSS to search in.
    """

    step = 600 # Stored in files each containing 10 minutes of traffic.   

    cntr = from_secs
    while True:
        anom_times = [cntr]
        cntr = cntr + 600
        if anom_times >= to_secs:
            break

    anom_times = map(get_pcap_date_suffix, anom_times)

    if anom_times[-1] != get_pcap_date_suffix(to_secs):
        anom_times.append(get_pcap_date_suffix(to_secs))

    return anom_times
