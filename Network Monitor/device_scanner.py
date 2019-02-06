#!/usr/bin/env python3

import datetime
from kamene.all import *
import sqlite3
from sqlite3 import Error
import socket 


def create_connection():
    try:
        conn = sqlite3.connect('network.db')
        return conn
    except Error as e:
        print(e)
    return None

def create_entry(conn, device):
    sql = ''' INSERT INTO devices(date,time,mac_addr,ip_addr)
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, device)

def get_Host_name_IP(): 
    try: 
        host_name = socket.gethostname() 
        my_ip = socket.gethostbyname(host_name) 
        return my_ip
    except: 
        print("Unable to get Hostname and IP")

def get_network():
	my_ip = get_Host_name_IP()
	parts = my_ip.split('.')
	parts[3] = '0/24'
	network = '{}.{}.{}.{}'.format(parts[0],parts[1],parts[2],parts[3])
	return network
	
def main():
	x = datetime.datetime.now()
	network = get_network()
	responses,unresponsive = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),timeout=2)
	conn = create_connection()
	for packet in responses: 
		mac_addr = packet[1][Ether].src 
		ip_addr = packet[1][ARP].psrc
		with conn:
			device = (x.strftime("%x"),x.strftime("%X"),str(mac_addr),str(ip_addr))
			create_entry(conn, device)

main()
