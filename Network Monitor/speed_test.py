#!/usr/bin/env python3

import sqlite3
from sqlite3 import Error
import datetime
import re
import os
import subprocess

def create_connection(db_file):
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
    return None

def create_entry(conn, test):
    sql = ''' INSERT INTO tests(date,time,download,upload,ping)
              VALUES(?,?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, test)

def main():
    database = "network.db"
    x = datetime.datetime.now()
    response = str(subprocess.Popen('/usr/local/bin/speedtest-cli --simple', shell=True, stdout=subprocess.PIPE).stdout.read())
    download = re.findall('Download:\s(.*?)\s', response, re.MULTILINE)
    upload = re.findall('Upload:\s(.*?)\s', response, re.MULTILINE)
    ping = re.findall('Ping:\s(.*?)\s', response, re.MULTILINE)
    # create a database connection
    conn = create_connection(database)
    with conn:
        test = (x.strftime("%x"),x.strftime("%X"),str(download[0]),str(upload[0]),ping[0])
        create_entry(conn, test)


main()
