#!/usr/bin/env python3
# coding=utf-8

import csv, json, sys
from fortiosapi.fortiosapi import fortiosapi
import getpass
from datetime import datetime

fw = input("FortiGate IP: ")
user = input("Username: ")
passwd = getpass.getpass()
proxy = None
output_file = open('policystats.csv', 'w')

try:
    t = fortiosapi(fw, user, passwd, proxies=proxy)
    data = json.loads(t.print_data(t.show("monitor/firewall/policy")))

    output = csv.writer(output_file)
    output.writerow(['policyid', 'last_used', 'bytes', 'packets'])
    for row in data:
        try: row['last_used']
        except KeyError: row['last_used'] = 0
        output.writerow([row['policyid'], datetime.utcfromtimestamp(row['last_used']).strftime('%Y-%m-%d'), row['bytes'], row['packets']])

    output_file.close()
except:
    print('something went wrong')
    raise
