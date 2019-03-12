# IoC-Collector

## Description
Collect Malware IoC, such as IP, Domain, Hash from Twitter.

## Requirements
Python 3 and the following libraries
 - requests
 - python-dateutil
 - pyquery

## Usage
- Show Help.

```sh
$ python3 ioc_collector.py -h
usage: ioc_collector.py [-h] [--query QUERY] [--users [USERS [USERS ...]]]
                        [--since SINCE] [--until UNTIL] [--output OUTPUT]
                        [--format {json,csv}] [--max-count MAX_COUNT]

optional arguments:
  -h, --help            show this help message and exit
  --query QUERY         Twitter Query
  --users [USERS [USERS ...]]
                        Twitter Users
  --since SINCE         Search since that date
  --until UNTIL         Search until that date
  --output OUTPUT       Output file name
  --format {json,csv}   Output Format
  --max-count MAX_COUNT
                        The number of Tweets
```

- Execute
```sh
python3 ioc_collector.py
```
Default Query is [this](https://twitter.com/search?f=tweets&vertical=default&q=virustotal.com%20OR%20app.any.run%20OR%20hybrid-analysis.com%20OR%20reverseit.com%20OR%20virusbay.io&src=typd&lang=ja&lang=ja).

- Execute with Custom Twitter Query
```sh
python3 ioc_collector.py --query '#Malware'
```

- Execute with Specific User
```sh
python3 ioc_collector.py --users userA userB
```

- Change output format (json or csv, and default is json)
```sh
python3 ioc_collector.py --format csv
```

- Change the number of tweets to be acquired (by default, 100 or more tweets are acquired)
```sh
python3 ioc_collector.py --max-count=1000
```

### Whitelist
This script is not perfect.
You can exclude false positives using the whitelist.

- IP Adress/Network
- Domain name or URL (describe as regular expression)

```
# IP Address whitelist
192.168.0.0/16
127.0.0.1

# Domain Name Or URL whitelist
^[A-Za-z0-9\-\.]*\.doc$
^[A-Za-z0-9\-\.]*\.txt$
.*(\.|/)virustotal.com$
```

## Author
[blueblue](https://twitter.com/piedpiper1616)
