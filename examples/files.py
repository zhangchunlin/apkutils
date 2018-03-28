#! /usr/bin/env python3
#coding=utf-8

import os

from apkutils import APK

file_path = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", 'data', 'test'))
apk = APK(file_path)

files = apk.get_files()
for item in files:
    print(item['name'])
