#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import pdb
import struct
import socket
import re

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
                config['rule']
        
        f=open(config['rule'],'r')
        rules=f.readlines()
        
        rules=[rule.strip("\n") for rule in rules]
        rules=[rule.split() for rule in rules]
        rules=[rule for rule in rules if len(rule) > 0 and (rule[0]=="pass" or rule[0]=="drop")]
        rules=rules[::-1]
       
        self.rules=rules #cleaned set of all rules that are in reverse priority

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

        f=open('geoipdb.txt','r')
        ip_ranges=f.readlines()
        
        ip_ranges=[ip_range.strip("\n") for ip_range in ip_ranges]
        ip_ranges=[ip_range.split(" ") for ip_range in ip_ranges]
        self.ip_ranges=ip_ranges


    def country_for_ip(self,ip): #expecting ip string
        ip_min=0
        ip_max=len(self.ip_ranges) 

        while True:
            index=(ip_min+ip_max)/2
            r=self.ip_ranges[index]

            if socket.inet_aton(r[0])<=ip and ip<=socket.inet_aton(r[1]): #in range
                return r[2]
            elif ip_max==index or ip_min==index:
                return None
            elif socket.inet_aton(r[1])<ip:
                ip_min=index
            elif socket.inet_aton(r[0])>ip:
                ip_max=index


    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.

        if self.should_ignore_packet(pkt):
            self.pass_packet(pkt,pkt_dir)
            return

        for rule in self.rules:
            if self.packet_matches_rule(pkt,pkt_dir,rule):
                if rule[0]=="pass":
                    self.pass_packet(pkt,pkt_dir)
                    print "--------------pass pkt-------------"
                elif rule[0]=="drop":
                    print "Dropped packet according to rule:", rule 
                return
       
        print "----passing since no rules-----"
        self.pass_packet(pkt,pkt_dir)


    def pass_packet(self,pkt, pkt_dir):
        if pkt_dir==PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir==PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)
 
    # TODO: You can add more methods as you want.

    def packet_matches_rule(self,pkt,pkt_dir,rule):
        pkt_protocol=struct.unpack('!B',pkt[9:10])[0]
        ipid=struct.unpack('!H',pkt[4:6])               #TODO: Do we need this?
        rule_protocol=rule[1]

        udp_pkt = self.strip_ip(pkt)
        dns_proto = rule_protocol=="dns"
        is_outgoing = int(pkt_dir)==PKT_DIR_OUTGOING
        correct_port = struct.unpack('!BB',udp_pkt[2:4])[1] == 53
        if dns_proto and is_outgoing and correct_port:
            dns_pkt = udp_pkt[8:]
            query = dns_pkt[12:]
            rule_name = re.split("\.", rule[2])[::-1]
            query_name = query.split("\x00")[0]
            query_name = re.split("\W+", query_name)[::-1]
            query_name = [q for q in query_name if q != '']
            query_type = re.split("\x00*", query)[1]
            query_class = re.split("\x00*", query)[2]
            class_match = ord(query_class)==1
            type_match = (ord(query_type) == 1 or ord(query_type) == 28)
            if class_match and type_match:
                i = 0
                while i < len(rule_name) and i < len(query_name):
                    if rule_name[i] == "*":
                        return True
                    if rule_name[i] != query_name[i]:
                        return False
                    i += 1
                return len(rule_name) == len(query_name)
            return False

        else:
            if pkt_protocol==17:
                pkt_protocol="udp"
            elif pkt_protocol==6:
                pkt_protocol="tcp"
            elif pkt_protocol==1:
                pkt_protocol="icmp"

            if pkt_protocol!=rule_protocol:
                return False

            src_ip=pkt[12:16]
            dst_ip=pkt[16:20]

            if rule[2]!="any":
                if len(rule[2])==2 and rule[2]!=self.country_for_ip(src_ip):
                    return False
                elif rule[2]!=socket.inet_ntoa(src_ip):
                    return False

            protocol_pkt=self.strip_ip(pkt)

            src_port=protocol_pkt[0:2]
            dest_port=protocol_pkt[2:4]

            if rule[3]!=src_port:
                return False

    def strip_ip(self,pkt):
        ip_header_len=(struct.unpack('!B',pkt[0:1])[0]&0xF)*4
        return pkt[ip_header_len:] 

    def should_ignore_packet(self,pkt):
        protocol=struct.unpack('!B',pkt[9:10])[0]
        if protocol!=17 and protocol!=6 and protocol!=1:
            return True
        else:
            return False


# TODO: You may want to add more classes/functions as well.
