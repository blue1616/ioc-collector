# IoC-Collector

## 概要
TwitterからマルウェアのIoC情報(IP、ドメイン、ハッシュなど)を収集するためのツールです。

## Requirements
Python3 及び以下のライブラリが必要です
 - requests
 - python-dateutil
 - pyquery

## 使い方
- Helpの通りです

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

- 実行
```sh
python3 ioc_collector.py
```
デフォルトのクエリは [こちら](https://twitter.com/search?f=tweets&vertical=default&q=virustotal.com%20OR%20app.any.run%20OR%20hybrid-analysis.com%20OR%20reverseit.com%20OR%20virusbay.io&src=typd&lang=ja&lang=ja).

- Twitterクエリをカスタマイズする
```sh
python3 ioc_collector.py --query '#Malware'
```

- ユーザを指定して実行する
```sh
python3 ioc_collector.py --users userA userB
```

- 出力フォーマットを変更する(json もしくは csv, デフォルトでは json になっています)
```sh
python3 ioc_collector.py --format csv
```

- 取得するツイートの数を変更する(デフォルトでは100以上のツイートを取得します)
```sh
python3 ioc_collector.py --max-count=1000
```

### Whitelist
このスクリプトは完璧ではありません.
ホワイトリストを用いて False Positive を除外しできます.

- IP アドレス/ネットワーク
- ドメイン名、URL(正規表現で記述する)

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
