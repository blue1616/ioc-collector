import argparse
import csv
import datetime
from dateutil import parser
import json
import ipaddress
import os
from pyquery import PyQuery
import re
import requests
import time
import urllib

whitelist = ['']

def getIoCPattern():
  md5_patt = r'\b(?!^[\d]*$)(?!^[a-fA-F]*$)([a-f\d]{32}|[A-F\d]{32})\b'
  sha1_patt = r'\b(?!^[\d]*$)(?!^[a-fA-F]*$)([a-f\d]{40}|[A-F\d]{40})\b'
  sha256_patt = r'\b(?!^[\d]*$)(?!^[a-fA-F]*$)([a-f\d]{64}|[A-F\d]{64})\b'
  ip_patt = r'\b(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\.)){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b'
  domain_patt = r'\b((([a-z0-9][a-z0-9\-]{0,61})(\.))+[a-z]{2,}|(([A-Z0-9][A-Z0-9\-]{0,61})(\.))+[A-Z]{2,})\b'
  url_patt = r'\b([a-zA-Z]*(://|//|/))?(((([a-z0-9][a-z0-9\-]{0,61})(\.))+[a-z]{2,}|(([A-Z0-9][A-Z0-9\-]{0,61})(\.))+[A-Z]{2,}(:[0-9]{1,5})?)|((([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\.)){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(:[0-9]{1,5})?))(/[\w/:%#$&?()~.=+\-\[\]]*)?\b'
  refer_url_patt = r'(https?)://((([A-Za-z0-9][A-Za-z0-9\-]{0,61})\.)+[A-Za-z]+)/([\w/:%#$&?()~.=+\-]*)?'
  mail_addr_patt = r'\b[a-zA-Z0-9.!#$%&\'*+\/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b'

  pattern = {}
  pattern['md5'] = re.compile(md5_patt)
  pattern['sha1'] = re.compile(sha1_patt)
  pattern['sha256'] = re.compile(sha256_patt)
  pattern['ip'] = re.compile(ip_patt)
  pattern['domain'] = re.compile(domain_patt)
  pattern['url'] = re.compile(url_patt)
  pattern['mail'] = re.compile(mail_addr_patt)
  pattern['reference'] = re.compile(refer_url_patt)

  return pattern

def loadWhitelist(filename):
  wl_file = open(filename, 'r')
  wl_ip_patt = re.compile(r'(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\.)){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([1-9]|[1-2][0-9]|3[0-2]))?')
  wl_ip = []
  wl_dom = []
  for line in wl_file.readlines():
    line = line.strip()
    if line != '':
      if line[0] == '#':
        continue
      if wl_ip_patt.match(line):
        wl_ip.append(line)
      else:
        try:
          wl_dom.append(re.compile(line, re.IGNORECASE))
        except:
          print('[-] Whitelist Regular Expression is wrong.')
          print('[-] Confirm Your String: ' + line)
  return wl_ip, wl_dom

def extract(data, patt):
  result = []
  while True:
    m = patt.search(data)
    if not m:
        break
    ioc = m.group()
    if not ioc in result:
      result.append(m.group())
    data = data[m.end():]
  return result

def extractIoC(data, pattern):
  wl_ip = []
  wl_dom = []
  if os.path.exists('whitelist'):
    (wl_ip, wl_dom) = loadWhitelist('whitelist')

  ioc_result = {}
  ioc_result['reference'] = extract(data, pattern['reference'])
  ioc_result['md5'] = extract(data, pattern['md5'])
  ioc_result['sha1'] = extract(data, pattern['sha1'])
  ioc_result['sha256'] = extract(data, pattern['sha256'])

  data = pattern['reference'].sub(' ' ,data)
  data = re.sub(r'pic\.twitter\.com\/[a-zA-Z0-9]+', ' ' ,data)

  dot_patt = r'\s\\\.|\\\.|\[\.\]|\[\.|\.\]|\(\.\)|\(\.|\.\)|\s\[\.\]|\s\[\.|\s\.\]|\s\(\.\)|\s\(\.|\s\.\)|\(dot\)'
  colon_patt = r'\[:\]|:\]|\[:'
  data = re.sub(dot_patt, '.', data)
  data = re.sub(colon_patt, '://', data)

  ioc_result['mail'] = extract(data, pattern['mail'])
  data = pattern['mail'].sub(' ' ,data)
  ioc_result['ip'] = extract(data, pattern['ip'])
  ioc_result['domain'] = extract(data, pattern['domain'])
  ioc_result['url'] = extract(data, pattern['url'])

  ioc_ip = ioc_result['ip'][:]
  for ip in ioc_result['ip']:
    for wl in wl_ip:
      if wl.find('/') >= 0:
        wl_nw = ipaddress.ip_network(wl)
        if ipaddress.ip_address(ip) in wl_nw and ip in ioc_ip:
          ioc_ip.remove(ip)
      else:
        if ip == wl and ip in ioc_ip:
          ioc_ip.remove(ip)
    if ip in ioc_result['url']:
      ioc_result['url'].remove(ip)
  ioc_result['ip'] = ioc_ip

  ioc_domain = ioc_result['domain'][:]
  for domain in ioc_result['domain']:
    isdomain = True
    for url in ioc_result['url']:
      d_pos = url.find(domain)
      if url == domain:
        ioc_result['url'].remove(domain)
      if d_pos > 0:
        tmp = url[:d_pos]
        if tmp.find('.') >= 0:
          if isdomain:
            ioc_domain.remove(domain)
          isdomain = False
    if isdomain:
      for wl in wl_dom:
        if wl.match(domain) and domain in ioc_domain:
          ioc_domain.remove(domain)
  ioc_result['domain'] = ioc_domain

  http_patt = [
    re.compile('^h(x|X)+p://[0-9a-zA-Z].*'),
    re.compile('^://[0-9a-zA-Z].*'),
    re.compile('^/{1,2}[0-9a-zA-Z].*')
  ]
  https_patt = [
    re.compile('^h(x|X)+ps://[0-9a-zA-Z].*'),
    re.compile('^s://[0-9a-zA-Z].*'),
    re.compile('^s/[0-9a-zA-Z].*')
  ]
  ioc_url = ioc_result['url'][:]
  for url in ioc_result['url']:
    for patt in http_patt:
      if patt.match(url):
        ioc_url[ioc_url.index(url)] = re.compile('^(h(x|X)+p://|://|/{1,2})').sub('http://' ,url)
    for patt in https_patt:
      if patt.match(url):
        ioc_url[ioc_url.index(url)] = re.compile('^(h(x|X)+ps://|s://|s/{1,2})').sub('https://' ,url)
    for wl in wl_dom:
      if wl.match(url) and url in ioc_url:
        ioc_url.remove(url)
        break
  ioc_result['url'] = ioc_url

  return ioc_result

def tweetPaser(tweets_html):
  tweetslist = []
  if tweets_html.strip() != '':
    scraped_tweets = PyQuery(tweets_html)
    scraped_tweets.remove('div.withheld-tweet')
    tweets = scraped_tweets('div.js-stream-tweet')
    if len(tweets) != 0:
      for tweet_html in tweets:
        t = {}
        tweetPQ = PyQuery(tweet_html)
        t['user'] = tweetPQ("span:first.username.u-dir b").text()
        txt = re.sub(r"\s+", " ", tweetPQ("p.js-tweet-text").text())
        txt = txt.replace('# ', '#')
        txt = txt.replace('@ ', '@')
        t['tweet'] = txt
        t['id'] = tweetPQ.attr("data-tweet-id")
        t['retweets'] = int(tweetPQ("span.ProfileTweet-action--retweet span.ProfileTweet-actionCount").attr("data-tweet-stat-count").replace(",", ""))
        t['favorites'] = int(tweetPQ("span.ProfileTweet-action--favorite span.ProfileTweet-actionCount").attr("data-tweet-stat-count").replace(",", ""))
        t['link'] = 'https://twitter.com' + tweetPQ.attr("data-permalink-path")
        t['mentions'] = re.compile('(@\\w+)').findall(t['tweet'])
        t['hashtags'] = re.compile('(#\\w+)').findall(t['tweet'])
        t['timestamp'] = int(tweetPQ("small.time span.js-short-timestamp").attr("data-time"))
        tweetslist.append(t)
  return tweetslist

def getCriteria(users, word, since, until):
  query = ''
  if word.strip() != '':
    query += word
  if len(users) == 1:
    query += ' from:' + users[0]
  elif len(users) > 1:
    query += ' from:' + ' OR from:'.join(users)
  if query == '':
    return query
  else:
    try:
      if since != None:
        since_day = parser.parse(since).strftime('%Y-%m-%d')
        query += ' since:' + since_day
      if until != None:
        until_day = parser.parse(until).strftime('%Y-%m-%d')
        query += ' until:' + until_day
    except ValueError:
      print('[-] Date Format Error')
  query = urllib.parse.quote_plus(query)
  return query

def getTweet(query, min_pos, max_count, tweets):
  url = 'https://twitter.com/i/search/timeline?f=tweets&q={query}&src=typd&max_position={min_pos}'.format(query=query, min_pos=min_pos)
  headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0',
    'Accept':"application/json, text/javascript, */*; q=0.01",
    'Accept-Language':"de,en-US;q=0.7,en;q=0.3",
    'X-Requested-With':"XMLHttpRequest",
    'Referer':url,
    'Connection':"keep-alive"
  }
  response = requests.get(url, headers=headers)
  statuscode = response.status_code
  json_response = response.json()
  if statuscode == 200:
    new_pos = None
    if 'min_position' in json_response:
      new_pos = json_response["min_position"]
    tweets += tweetPaser(json_response['items_html'])
    if new_pos == min_pos or len(tweets) > max_count:
      return tweets, statuscode
    else:
      proc = int((len(tweets) / max_count) * 100)
      print('[+] ' + str(proc) + '% Processing...')
      time.sleep(0.5)
      return getTweet(query, new_pos, max_count, tweets)
  else:
    print('[-] Something Wrong...\nStatus: ' + str(statuscode))
    return tweets, statuscode

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--query', type=str, default='', help='Twitter Query')
  parser.add_argument('--users', type=str, nargs='*', help='Twitter Users')
  parser.add_argument('--since', type=str, help='Search since that date')
  parser.add_argument('--until', type=str, help='Search until that date')
  parser.add_argument('--output', type=str, help='Output file name')
  parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output Format')
  parser.add_argument('--max-count', type=int, default=100, help='The number of Tweets')
  args = parser.parse_args()

  users = ''
  word = args.query
  if args.users != None:
    users = args.users
  since = args.since
  until = args.until
  if word == '' and users == '':
    print('[+] Query is Empty. Exit. Use Default Query.')
    word = 'virustotal.com OR app.any.run OR hybrid-analysis.com OR reverseit.com OR virusbay.io'
  query = getCriteria(users, word, since, until)
  max_count = args.max_count
  print('[+] Your Query is: ' + query)
  print('[+] You can Check your Results in the following URL.')
  print('[+] https://twitter.com/search?f=tweets&vertical=news&q={q}&src=typd&'.format(q=query))
  print('[+] Gathering Tweets. Please Wait...')
  (tweets, statuscode) = getTweet(query, 'min_pos', max_count, [])
  print('[+] Get {num} Tweets '.format(num=str(len(tweets))))
  print('[+] Save Twitter Search Result')
  ioc_pattaern = getIoCPattern()
  timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
  if args.format == 'json':
    if args.output == None:
      filename = 'ioc-collection-' + timestamp + '.json'
      f = open(filename, 'w')
    else:
      filename = args.output
      try:
        f = open(filename, 'w')
      except:
        print('[-] Cannot open ' + filename)
        filename = 'ioc-collection-' + timestamp + '.json'
        f = open(filename, 'w')
    json_result = []
    for t in tweets:
      iocs = extractIoC(t['tweet'], ioc_pattaern)
      iocs['tweet'] = t
      json_result.append(iocs)
    with open(filename, 'w') as f:
      json.dump(json_result, f, indent=4)
    print('[+] Tweets ware saved in ' + filename)
  elif args.format == 'csv':
    if args.output == None:
      filename = 'ioc-collection-' + timestamp + '.csv'
      f = open(filename, 'w')
    else:
      filename = args.output
      try:
        f = open(filename, 'w')
      except:
        print('[-] Cannot open ' + filename)
        filename = 'ioc-collection-' + timestamp + '.csv'
        f = open(filename, 'w')
    writer = csv.writer(f, lineterminator='\n')
    headers = ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256', 'mail', 'reference', 'tweet.user', 'tweet.text', 'tweet.id', 'tweet.link', 'tweet.RT', 'tweet.fav', 'tweet.mentions', 'tweet.hashtags', 'tweet.timestamp']
    writer.writerow(headers)
    for t in tweets:
      row = []
      iocs = extractIoC(t['tweet'], ioc_pattaern)
      row.append('\n'.join(iocs['ip']))
      row.append('\n'.join(iocs['domain']))
      row.append('\n'.join(iocs['url']))
      row.append('\n'.join(iocs['md5']))
      row.append('\n'.join(iocs['sha1']))
      row.append('\n'.join(iocs['sha256']))
      row.append('\n'.join(iocs['mail']))
      row.append('\n'.join(iocs['reference']))
      row.append(t['user'])
      row.append(t['tweet'])
      row.append(t['id'])
      row.append(t['link'])
      row.append(str(t['retweets']))
      row.append(str(t['favorites']))
      row.append('\n'.join(t['mentions']))
      row.append('\n'.join(t['hashtags']))
      row.append(datetime.datetime.fromtimestamp(t['timestamp']))
      writer.writerow(row)
    print('[+] Tweets ware saved in ' + filename)

if __name__ == "__main__":
  main()
