#!/usr/bin/env python3

# -*- coding: utf-8 -*-
import re

skids = set()
with open("./trace.log", 'r', encoding='utf8') as f:
    for line in f.readlines():
        if '-> 192.168.33.13:22' in line:
            for item in re.findall('.*skId:(\\d+)', line):
                skids.add(item)

with open("./link.log", 'w', encoding='utf8') as l:
    with open("./trace.log", 'r', encoding='utf8') as f:
        for line in f.readlines():
            exists = False
            for skid in skids:
                if skid in line:
                    exists = True
            if exists:
                l.write(line)
