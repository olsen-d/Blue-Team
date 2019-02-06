#!/usr/bin/env python3

import socket
import struct
import textwrap
import datetime
import sqlite3
from sqlite3 import Error


def main():
  database = 'network.db'
  conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
  c = create_connection(database)

  while True:
    x = datetime.datetime.now()
    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    
# For list of other Ethernet Protocols: https://en.wikipedia.org/wiki/EtherType    
    if eth_proto == 8:
      (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
      with c:
        #ICMP-1, IGMP-2, TCP-6, UDP-17, ENCAP-41, OSPF-89, SCTP-132
        if proto == 1:
          sql = 'INSERT INTO icmp_traffic(date,time,protocol,source_ip,dest_ip) VALUES(?,?,?,?,?)'
          packet = (x.strftime("%x"),x.strftime("%X"),'ICMP',src,target,'-','-','-')
          create_entry(sql, c, packet)
        elif proto == 6:
          (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin) = tcp_segment(data)
          sql = 'INSERT INTO tcp_traffic(date,time,protocol,source_ip,dest_ip, src_port,dest_port,flag ) VALUES(?,?,?,?,?,?,?,?)'
          packet = (x.strftime("%x"),x.strftime("%X"),'TCP',src,target, src_port, dest_port,'-')
          create_entry(sql, c, packet)
        elif proto == 17:
          src_port, dest_port, length, data = udp_segment(data)
          sql = 'INSERT INTO udp_traffic(date,time,protocol,source_ip,dest_ip, src_port,dest_port,flag ) VALUES(?,?,?,?,?,?,?,?)'
          packet = (x.strftime("%x"),x.strftime("%X"),'UDP',src,target, src_port, dest_port,'-')
          create_entry(sql, c, packet)
        else:
          sql = 'INSERT INTO other_traffic(date,time,type, protocol,source_ip,dest_ip) VALUES(?,?,?,?,?,?,?,?)'
          packet = (x.strftime("%x"),x.strftime("%X"),src,target,'Other', '-', '-','-')
          create_entry(sql, c, packet)
    elif eth_proto == 1544:
      sql = 'INSERT INTO arp_traffic(date,time,type,source_mac,dest_mac) VALUES(?,?,?,?,?)'
      packet = (x.strftime("%x"),x.strftime("%X"),'ARP',src_mac,dest_mac)
      create_entry(sql, c, packet)
      
    else:
      sql = 'INSERT INTO other_traffic(date,time,type, protocol,source_ip,dest_ip) VALUES(?,?,?,?,?,?)'
      packet = (x.strftime("%x"),x.strftime("%X"),eth_proto,'?','-','-')
      create_entry(c, packet)

#Unpacks ethernet frame
def ethernet_frame(data):
  dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
  return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

#Return properly formatted MAC address (ie. AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
  bytes_str = map('{:02x}'.format, bytes_addr)
  mac_addr = ':'.join(bytes_str).upper()
  return mac_addr

#Unpacks IPV4 packet
def ipv4_packet(data):
  version_header_length = data[0]
  version = version_header_length >> 4
  header_length = (version_header_length & 15) * 4
  ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
  return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#Returns properly formatted IPV4 address
def ipv4(addr):
  return '.'.join(map(str, addr))

#Unpacks ICMP packet
def icmp_packet(data):
  icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
  return icmp_type, code, checksum, data[4:]

#Unpacks TCP segment
def tcp_segment(data):
  (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
  offset = (offset_reserved_flags >> 12) * 4
  flag_urg = (offset_reserved_flags & 32) >> 5
  flag_ack = (offset_reserved_flags & 32) >> 4
  flag_psh = (offset_reserved_flags & 32) >> 3
  flag_rst = (offset_reserved_flags & 32) >> 2
  flag_syn = (offset_reserved_flags & 32) >> 1
  flag_fin = offset_reserved_flags & 1
  return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin

#Unpacks UDP segment
def udp_segment(data):
  src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
  return src_port, dest_port, size, data[8:]

#Formats multi-line data
def format_multi_line(prefix, string, size=80):
  size -= len(prefix)
  if isinstance(string, bytes):
    string = ''.join(r'\x{}:02x}'.format(byte) for byte in string)
    if size %2:
      size -= 1
  return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

#Connect to database:
def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    try:
        c = sqlite3.connect(db_file)
        return c
    except Error as e:
        print(e)
    return None

def create_entry(sql,c, packet):
    """
    Create a new packet
    :param conn:
    :param packet:
    :return:
    """

    #sql = ''' INSERT INTO traffic(date,time,source_ip,dest_ip,protocol,src_port,dest_port,flag)
    #          VALUES(?,?,?,?,?,?,?,?) '''
    cur = c.cursor()
    cur.execute(sql, packet)
    return cur.lastrowid


main()
