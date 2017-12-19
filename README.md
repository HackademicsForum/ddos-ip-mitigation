# ddos-ip-mitigation
This repository is aimed to present a DDOS mitigation tool used and created by Hackademics community member AnOnyme77. 

This tool is written in pure Python3 with no external dependencies and have two main usages : 

1. Analyze nginx log file to group log lines in "time groups" of a defined size (that can be changed)
2. Analyze nginx log file to get individuals IP that made queries in a given time interval. 

Usual usage is as follow : 

1. Run the first option to discover the DDOS attack start timestamp. The starting of the attack can be discover because of the big raising in the number of connections per time block
2. Run the second option to extract the IP addresses found in logs since the start of the attack and a choosen end time. Please note that choosing a end time 'far away' from the start time increase the number of attackers IP addresses detection but also the number of legitim client IP addresses that would be blocked
3. Manually (or via a script) block the previously discovered IP addresses thanks to firewall rules. 

## Manual of the script

```
usage: mitigate_DDOS.py [-h] -f NGINX_LOG_FILE [-a] [-t TIME] [-i]
                        [-b BEGIN_TIMESTAMP] [-e END_TIMESTAMP]

Analyzes web server logs to find begin and mitigate DDOS attack

optional arguments:
  -h, --help          show this help message and exit
  -f NGINX_LOG_FILE   The nginx log file
  -a                  Analysis task
  -t TIME             Time split for log blocks (default 10)
  -i                  Get IPs between two timestamps
  -b BEGIN_TIMESTAMP  Begin timestamp (in seconds) for IP gathering
  -e END_TIMESTAMP    Begin timestamp (in seconds) for IP gathering
```

## Possible enhancements
Possible enhancements are : 

* Add supports for Apache log file format
* Auto-detect possible attack start
