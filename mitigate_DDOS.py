"""Script to mitigate a ddos attack by analyzing web log log file"""


import os
import sys
from collections import namedtuple
import datetime
import argparse


LogLine = namedtuple("LogLine", "ip time")


class NginxLogDao():
    """Data access object for NginxLog"""

    def __init__(self, filename):
        """Initialises this with given filename"""

        assert filename is not None
        assert os.path.exists(filename)

        self.filename = filename

    def log_lines(self):
        """Reads logs lines and returns them as named tuples"""

        with open(self.filename) as f:
            for line in f:
                ip = line.split("-")[0].strip()
                date_str = line.split("[")[1].split("]")[0].split(" ")[0]
                date = datetime.datetime.strptime(
                    date_str, '%d/%b/%Y:%H:%M:%S')
                yield LogLine(ip=ip, time=date)

    def time_grouped(self, time_size=10):
        """Returns log lines grouped in time groups with blocks 
           of time_size seconds"""

        block = None
        block_begin = None
        for log_line in self.log_lines():
            if block_begin is None or log_line.time > block_begin \
                    + datetime.timedelta(seconds=time_size):
                if block_begin is not None:
                    yield block

                block_begin = log_line.time
                block = list()

            block.append(log_line)

    def ips_between(self, dt1, dt2):
        """Returns set of ip addresses between two timestamps"""

        ips = set()
        for log_line in self.log_lines():
            if dt1 <= log_line.time <= dt2:
                ips.add(log_line.ip)
            elif log_line.time > dt2:
                break

        return list(ips)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Analyzes web server logs to find begin and mitigate DDOS attack')
    parser.add_argument('-f', action="store", dest="nginx_log_file",
                        help="The nginx log file", required=True)
    parser.add_argument('-a', action="store_true", dest="analyze",
                        help="Analysis task")
    parser.add_argument('-t', action="store", dest="time",
                        help="Time split for log blocks (default 10)",
                        default=10)
    parser.add_argument('-i', action="store_true", dest="get_ip",
                        help="Get IPs between two timestamps")
    parser.add_argument('-b', action="store", dest="begin_timestamp",
                        help="Begin timestamp (in seconds) for IP gathering")
    parser.add_argument('-e', action="store", dest="end_timestamp",
                        help="Begin timestamp (in seconds) for IP gathering")
    params = parser.parse_args()

    if params.analyze:
        time = int(params.time)
        blocks = NginxLogDao(
            params.nginx_log_file).time_grouped(time_size=time)
        for block in blocks:
            block_start = block[0].time
            timestamp = int(block_start.timestamp())
            print("{} - {} - {}".format(block_start, timestamp, len(block)))
    elif params.get_ip:
        if params.begin_timestamp is None or params.end_timestamp is None:
            print("With option -i you must provide option -b and -e")
            sys.exit(1)

        begin_timestamp = datetime.datetime.fromtimestamp(int(params.begin_timestamp))
        end_timestamp = datetime.datetime.fromtimestamp(int(params.end_timestamp))

        ips = NginxLogDao(params.nginx_log_file).ips_between(begin_timestamp,
                                                             end_timestamp)
        for ip in ips:
            print(ip)
