#!/usr/bin/env python3
#TO DO: 
## Double check that network_sniffer starts upon reboot.  
## Add input so user can select network_monitor directory
## Add dependency check/download

import os
import subprocess
import sqlite3
from sqlite3 import Error
from crontab import CronTab

#Check for Admin privs
def check_for_admin():
	user = (os.getuid())
	if user != 0:
		print('You must have admin privileges to install.')
		exit()
		
#Check that files are available
def check_for_files():
	py_files = ['/home/pi/run_test.py', '/home/pi/device_scan.py']
	for file in py_files:
		if os.path.isfile(file) == False:
			print('%s file is missing.' % file)

#Create crontab entries for scheduled tasks
def schedule_jobs():
	schD_tasks = ['sudo python3 /home/pi/device_scan.py', 
			'sudo python3 /home/pi/run_test.py']		
	start_tasks = ['sudo python3 /home/pi/network_sniffer.py']

	cron = CronTab(user='pi')  
	for task in schD_tasks:
		job = cron.new(command = task, comment = 'Network_Monitor')  
		job.minute.every(15)
		cron.write()  
 
	for task in start_tasks:
		job = cron.new(command = task, comment = 'Network_Monitor')  
		job.every_reboot()
		cron.write()  
	
	
#Check for modules and download if necessary
#Create databases
def create_connection(db_file):
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
    return None

def create_table(conn, create_table_sql):
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)
    return
#
def create_dbs():
    database = "network.db"
    sql_create_tests_table = """CREATE TABLE IF NOT EXISTS tests (
                                    date text,
                                    time text,
                                    download integer,
                                    upload integer,
                                    ping integer
                                );"""
    sql_create_arp_traffic_table = """CREATE TABLE IF NOT EXISTS arp_traffic (
                                    date text,
                                    time text,
                                    protocol string,
                                    type text,
                                    source_mac text,
                                    dest_mac text
                                );"""
    sql_create_icmp_traffic_table = """CREATE TABLE IF NOT EXISTS icmp_traffic (
                                    date text,
                                    time text,
                                    protocol string,
                                    source_ip text,
                                    dest_ip text
                                );"""
    sql_create_tcp_traffic_table = """CREATE TABLE IF NOT EXISTS tcp_traffic (
                                    date text,
                                    time text,
                                    protocol string,
                                    source_ip text,
                                    dest_ip text,
                                    src_port text,
                                    dest_port text,
                                    flag text
                                );"""
    sql_create_udp_traffic_table = """CREATE TABLE IF NOT EXISTS udp_traffic (
                                    date text,
                                    time text,
                                    protocol string,
                                    source_ip text,
                                    dest_ip text,
                                    src_port text,
                                    dest_port text,
                                    flag text
                                );"""
    sql_create_other_traffic_table = """CREATE TABLE IF NOT EXISTS other_traffic (
                                    date text,
                                    time text,
                                    type string,
                                    protocol text,
                                    source_ip text,
                                    dest_ip text
                                );"""
    sql_create_devices_table = """CREATE TABLE IF NOT EXISTS devices (
                                    date text,
                                    time text,
                                    mac_addr text,
                                    ip_addr text
                                );"""


    conn = create_connection(database)
    if conn is not None:
        #Create 6 tables 
        create_table(conn, sql_create_tests_table)
        create_table(conn, sql_create_arp_traffic_table)
        create_table(conn, sql_create_tcp_traffic_table)
        create_table(conn, sql_create_udp_traffic_table)
        create_table(conn, sql_create_other_traffic_table)
        create_table(conn, sql_create_icmp_traffic_table)
        create_table(conn, sql_create_devices_table)
    else:
        print("Error! cannot create the database connection.")



check_for_admin()
check_for_files()
create_dbs()
schedule_jobs()

print("Installation is complete!")
