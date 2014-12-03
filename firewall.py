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
        
        f=open(config['rule'],'r')
        rules=f.readlines()
        
        rules=[rule.strip("\n").lower() for rule in rules]
        rules=[rule.split() for rule in rules]
        rules=[rule for rule in rules if len(rule) > 0 and (rule[0]=="pass" or rule[0]=="drop" or rule[0]=="log" or rule[0]=="deny")]
        rules=rules[::-1]
       
        self.rules=rules #cleaned set of all rules that are in reverse priority

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

        f=open('geoipdb.txt','r')
        ip_ranges=f.readlines()
        
        ip_ranges=[ip_range.strip("\n").lower() for ip_range in ip_ranges]
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
        if struct.unpack('!B',pkt[9:10])[0]==17:
            self.udp_checksum(pkt) 
            
        ip=""
        src_ip=pkt[12:16]
        dst_ip=pkt[16:20]
        if pkt_dir == PKT_DIR_OUTGOING:
            ip = dst_ip
        else:
            ip = src_ip

        country=self.country_for_ip(ip)
        for rule in self.rules:
            if self.packet_matches_rule(pkt,pkt_dir,rule,country):
                if rule[0]=="pass":
                    self.pass_packet(pkt,pkt_dir)
                elif rule[0]=="drop":
                    print "Dropped packet according to rule:", rule, self.eval_pkt(pkt)
                elif rule[0]=="deny" and rule[1]=="dns":
                    print "Deny accoring to rule:", rule, self.eval_pkt(pkt)
                    self.send_dns_response(pkt,pkt_dir)
                elif rule[0]=="deny" and rule[1]=="tcp":
                    print "Deny accoring to rule:", rule, self.eval_pkt(pkt)
                    self.send_tcp_response(pkt,pkt_dir)
                return
        self.pass_packet(pkt,pkt_dir)


    def eval_pkt(self,pkt):
        pkt_protocol=struct.unpack('!B',pkt[9:10])[0]
        src_ip=socket.inet_ntoa(pkt[12:16])
        dest_ip=socket.inet_ntoa(pkt[16:20])

        protocol_pkt=self.strip_ip(pkt)

        src_port=struct.unpack('!H',protocol_pkt[0:2])[0]
        dest_port=struct.unpack('!H',protocol_pkt[2:4])[0]

        return "Packet:"+src_ip+":"+str(src_port)+" --> "+dest_ip+":"+str(dest_port)+ " w/protocol "+str(pkt_protocol)


    def pass_packet(self,pkt, pkt_dir):
        if pkt_dir==PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir==PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    #sends a denial packet in the OPPOSITE direction pkt_dir
    def send_deny_pkt(self, pkt, pkt_dir):
        if pkt_dir==PKT_DIR_INCOMING:
            self.iface_ext.send_ip_packet(pkt)
        elif pkt_dir==PKT_DIR_OUTGOING:
            self.iface_int.send_ip_packet(pkt)

    # TODO: You can add more methods as you want.
    def dns_check(self,pkt,pkt_dir):
        udp_pkt = self.strip_ip(pkt)
        if len(udp_pkt) >= 20:
            dns_pkt = udp_pkt[8:]
            query = dns_pkt[12:]
            query_split = re.split("\x00*", query)
            query_split = [q for q in query_split if q != ""]
            if len(query_split) >= 3:
                query_type = re.split("\x00*", query)[1]
                query_class = re.split("\x00*", query)[2]
                class_match = ord(query_class[0])==1
                type_match = (ord(query_type[0]) == 1 or ord(query_type[0]) == 28)
                is_outgoing = int(pkt_dir)==PKT_DIR_OUTGOING
                port_match = struct.unpack('!BB',udp_pkt[2:4])[1] == 53
                one_question = struct.unpack('!H',dns_pkt[4:6])[0] == 1
                return class_match and type_match and is_outgoing and port_match and one_question
        return False

    def read_qname(self, dns_pkt):
        next_len = 12
        length = struct.unpack('!B', dns_pkt[next_len])[0]
        while length != 0:
            next_len += length + 1
            length = struct.unpack('!B', dns_pkt[next_len])[0]
        return dns_pkt[12:next_len + 1]

    def send_dns_response(self, pkt, pkt_dir):
        udp_pkt = self.strip_ip(pkt)
        dns_pkt = udp_pkt[8:]
        qname = self.read_qname(dns_pkt)
        answer = qname + struct.pack('!H', 1)
        answer += struct.pack('!H', 1) + struct.pack('!L', 1) + struct.pack('!H', 4)
        answer += struct.pack('!B', 54) + struct.pack('!B', 173) + struct.pack('!B', 224) + struct.pack('!B', 150)
        dns_header = dns_pkt[0:2] + struct.pack('!B', (struct.unpack('!B',dns_pkt[2])[0]|0x80)&0xf9)
        dns_header += struct.pack('!L', 0) + struct.pack('!B', 1) + struct.pack('!L', 0)
        dns_header += answer
        udp_header = "%s%s%s%s" % (udp_pkt[2:4],udp_pkt[0:2],struct.pack('!H',8),struct.pack('!H',0))
        udp_header += dns_header
        ip_header = struct.pack('!H',0x4500) + struct.pack('!H', len(udp_header)) + pkt[4:6] + struct.pack('!H',0)
        ip_header += struct.pack('!B',1) + struct.pack('!B',17) + struct.pack('!H',0) + pkt[16:20] + pkt[12:16]
        ip_header += dns_header

        ip_header=self.udp_checksum(ip_header)
        new_pkt=self.ip_checksum(ip_header)
        self.send_deny_pkt(new_pkt, pkt_dir)

    def send_tcp_response(self,pkt,pkt_dir):
        pkt=self.swap_ip(pkt)
        tcp_pkt=self.strip_ip(pkt)
        new_seq=struct.pack('!L',struct.unpack('!L',tcp_pkt[8:12])[0]) 
        new_ack=struct.pack('!L',struct.unpack('!L',tcp_pkt[4:8])[0]+1)
        new_tcp_pkt=tcp_pkt[2:4]+tcp_pkt[0:2]+new_seq+new_ack+tcp_pkt[12]+0x04+tcp_pkt[14:16]+struct.pack('!L',0)+tcp_pkt[18:]

        ip_header_len=(struct.unpack('!B',pkt[0:1])[0]&0xF)*4
        new_pkt=pkt[:ip_header_len] + new_tcp_pkt
        self.send_deny_pkt(new_pkt,pkt_dir)

    def swap_ip(self,pkt):
        ttl=struct.pack('!B',255)
        checksum=struct.pack('!H',0)   #originally zero
        new_pkt=pkt[:8]+ttl+pkt[9]+checksum+pkt[16:20]+pkt[12:16]+pkt[20:]
        new_pkt=self.ip_checksum(new_pkt)
        return new_pkt 

    def udp_checksum(self,pkt):
        udp_pkt=self.strip_ip(pkt)
        ip_header_len=(struct.unpack('!B',pkt[0:1])[0]&0xF)*4
        ip_header=pkt[:ip_header_len]
        print "OLD UDP", struct.unpack('!H',udp_pkt[6:8])
        udp_pkt=udp_pkt[0:6]+struct.pack('!B',0)+udp_pkt[8:]
        checksum=struct.pack('!H',self.checksum(pkt[12:16]+pkt[16:20]+struct.pack('!B',0)+pkt[9:10]+udp_pkt[4:6]))
        print "New UDP", struct.unpack('!H',checksum)
        return ip_header+udp_pkt[0:6]+checksum+udp_pkt[8:]

    def ip_checksum(self,pkt):
        ip_header_len=(struct.unpack('!B',pkt[0:1])[0]&0xF)*4
        ip_header=pkt[:ip_header_len] 
        ip_header=ip_header[:10]+struct.pack('!H',0)+ip_header[12:]
        new_ip_header=ip_header[:10]+struct.pack('!H',self.checksum(ip_header))+ip_header[12:]
        return new_ip_header+pkt[ip_header_len:] 

    def checksum(self,s):
        total=0
        for i in xrange(len(s)/2):
            total=total+struct.unpack('!H',s[i*2:(i+1)*2])[0]
        if len(s)%2==1:
            total=total+struct.unpack('!B',s[-1])[0]

        while not total>>16 == 0:
            total= (total>>16) + total&0xffff

        return (~total)&0xffff

    def packet_matches_rule(self,pkt,pkt_dir,rule,country):
        pkt_protocol=struct.unpack('!B',pkt[9:10])[0]
        ipid=struct.unpack('!H',pkt[4:6])               #TODO: Do we need this?
        rule_protocol=rule[1]
        udp_pkt = self.strip_ip(pkt)
        dns_proto = rule_protocol=="dns"
        if dns_proto and pkt_protocol==17:
            if self.dns_check(pkt,pkt_dir):
                dns_pkt = udp_pkt[8:]
                query = dns_pkt[12:]
                rule_name = re.split("\.", rule[2])[::-1]
                query_name = query.split("\x00")[0]
                query_name = re.split("\W+", query_name)[::-1]
                query_name = [q for q in query_name if q != '']
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

            if rule[2]!="any":   # ip address
                if pkt_dir == PKT_DIR_OUTGOING:
                    ip = dst_ip
                else:
                    ip = src_ip
                if "/" in rule[2]:
                    ip_prefix=rule[2].split("/")
                    mask= (pow(2,int(ip_prefix[1]))-1)<<(32-int(ip_prefix[1]))
                    if struct.unpack('!L',socket.inet_aton(ip_prefix[0]))[0]&mask!=struct.unpack('!L',ip)[0]&mask:
                        return False
                elif len(rule[2])==2 and rule[2]!=country:
                    return False
                elif len(rule[2])!=2 and rule[2]!=socket.inet_ntoa(ip):
                    return False

            protocol_pkt=self.strip_ip(pkt)

            src_port=struct.unpack('!H',protocol_pkt[0:2])[0]
            if pkt_protocol=="icmp":
                src_port=struct.unpack('!B',protocol_pkt[0])[0]

            dest_port=struct.unpack('!H',protocol_pkt[2:4])[0]
            if pkt_dir == PKT_DIR_OUTGOING and pkt_protocol!="icmp":
                port = dest_port
            else:
                port = src_port

            if rule[3]!="any":                             # port
                if "-" in rule[3]: #port range
                    port_range=rule[3].split("-")
                    if int(port_range[0])<=port and port<=int(port_range[1]):
                        return True
                    else:
                        return False
                if rule[3]!=str(port):   
                    return False

            return True

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
