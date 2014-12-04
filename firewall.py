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
        rules=[rule for rule in rules if len(rule) > 0 and (rule[0]=="pass" or rule[0]=="drop")]
        rules=rules[::-1]

        log_rules=[rule for rule in rules if len(rule) >= 3 and rule[0] == "log" and rule[1] == "http"]
        rules = [rule for rule in rules if len(rule) >= 2 and rule[0] != "log"]

        self.rules=rules #cleaned set of all rules that are in reverse priority

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

        f=open('geoipdb.txt','r')
        ip_ranges=f.readlines()
        
        ip_ranges=[ip_range.strip("\n").lower() for ip_range in ip_ranges]
        ip_ranges=[ip_range.split(" ") for ip_range in ip_ranges]
        self.ip_ranges=ip_ranges
        
        # http persistent connections
        self.http_flows = {} # format (int_port, dest_ip):(next_seqno,pkt_dir,data_in,data_out, established)
        self.counter = 1
        self.pdbinterval = 10

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
                    if self.is_http(pkt, pkt_dir):
                        if self.put_http_together(pkt, pkt_dir):
                            self.pass_packet(pkt,pkt_dir)
                    else:
                        self.pass_packet(pkt,pkt_dir)
                elif rule[0]=="drop":
                    print "Dropped packet according to rule:", rule, self.eval_pkt(pkt)
                return
        self.pass_packet(pkt,pkt_dir)

    def is_http(self, pkt, pkt_dir):
        pkt_protocol=struct.unpack('!B',pkt[9:10])[0]
        if pkt_protocol == 6:
            tcp_pkt = self.strip_ip(pkt)
            if len(tcp_pkt) >= 20:
                incoming_80 = pkt_dir == PKT_DIR_INCOMING and int(struct.unpack('!H', tcp_pkt[0:2])[0]) == 80
                outgoing_80 = pkt_dir == PKT_DIR_OUTGOING and int(struct.unpack('!H', tcp_pkt[2:4])[0]) == 80
                return incoming_80 or outgoing_80
            return False
        else:
            return False

    def log_rule_matches(self, host_name, rule, pkt_dir):
        if host_name == rule[2]:
            return True
        else:
            rulename = rule[2].split('.')[::-1]
            hostname = host_name.split('.')[::-1]
            i = 0
            while i < len(hostname) and i < len(rulename):
                if rulename[i] == '*':
                    return True
                elif rulename[i] != hostname[i]:
                    return False
            return len(hostname) == len(rule_name)

    def write_http(self, key):
        val = self.http_flows[key]
        logfile = open('http.log', 'a')
        split_req = val[2].split()
        h_match = re.search('Host:\s+(?P<hostname>\w+)', val[2])
        if h_match:
            host_name = h_match.group('hostname')
            if type(host_name) == tuple:
                host_name = host_name[0]
        else:
            host_name = key[1]
        method = split_val[0]
        path = split_val[1]
        version = split_val[2]
        status_code = val[3].split()[1]
        os_match = re.search('Content-Length:\s+(?P<objsize>\w+)', val[3])
        if os_match:
            object_size = os_match.group('objsize')
            if type(object_size) == tuple:
                object_size = object_size[0]
        else:
            object_size = '-1'
        log = "%s %s %s %s %s %s" % (host_name, method, path, version, status_code, object_size)
        for rule in log_rules:
            if log_rule_matches(host_name, rule, pkt_dir):
                logfile.write(log)
                logfile.flush()
        self.http_flows[key][2] = ''
        self.http_flows[key][3] = ''

    def put_http_together(self, pkt, pkt_dir):
        #if we keep this packet, return true. if we drop this packet due to out-of-order, we return false
        #do the logging stuff here
        tcp_pkt = self.strip_ip(pkt)
        seqno = int(struct.unpack('!L', tcp_pkt[4:8])[0])
        ackno = int(struct.unpack('!L', tcp_pkt[8:12])[0])
        if pkt_dir == PKT_DIR_OUTGOING:
            port = struct.unpack('!H',tcp_pkt[0:2])[0]
            ip_addr = struct.unpack('!L',pkt[16:20])[0]
        else:
            port = struct.unpack('!H',tcp_pkt[2:4])[0]
            ip_addr = struct.unpack('!L',pkt[12:16])[0]
        key = (port, ip_addr)
        http_pkt = self.strip_tcpip(pkt)
        direction = ("<---INCOMING", "--->OUTGOING")
        print str(key) + ":SN=" + str(seqno) + ", ACK=" + str(ackno) + direction[pkt_dir]
        if key in self.http_flows:
            val = self.http_flows[key]
            print "expecting SN/ACK " + str(val[0])
            if val[4] == 0:
                if pkt_dir == PKT_DIR_INCOMING and ackno == val[0] + 1:
                    self.http_flows[key] = (val[0] + 1, val[1], val[2], val[3], 1)
                    return True
                else:
                    return False
            elif val[4] == 1:
                if pkt_dir == PKT_DIR_OUTGOING and seqno == val[0]:
                    self.http_flows[key] = (val[0], val[1], val[2], val[3], 2)
            elif pkt_dir == PKT_DIR_OUTGOING and seqno == val[0]:
                data = self.strip_tcpip(pkt)
                if pkt_dir == PKT_DIR_OUTGOING:
                    out_data = val[2] + http_pkt
                    new_pkt_dir = pkt_dir
                    self.counter += 1
                    #if self.counter % self.pdbinterval == 0:
                    #    pdb.set_trace()
                    if re.search("\r\n\r\n", out_data):
                        print "outgoing packet finished"
                        new_pkt_dir = PKT_DIR_INCOMING
                    self.http_flows[key] = (seqno + len(data) - 20, new_pkt_dir, out_data, val[3], val[4])
                if pkt_dir == PKT_DIR_INCOMING:
                    write = False
                    in_data = val[3] + http_pkt
                    new_pkt_dir = pkt_dir
                    self.counter += 1
                    #if self.counter % self.pdbinterval == 0:
                    #pdb.set_trace()
                    if re.search("\r\n\r\n", in_data):
                        new_pkt_dir = PKT_DIR_OUTGOING
                        write = True
                    self.http_flows[key] = (seqno + len(data) - 20, new_pkt_dir, val[2], in_data, val[4])
                    if write:
                        self.write_http(key)
                return True
            elif pkt_dir == PKT_DIR_INCOMING and ackno == val[0]:
                self.http_flows[key] = (val[0], val[1], val[2], val[3], val[4])
                return True
            elif val[0] > seqno:
                return True
            else:
                print "DROP"
                return False
        else:
            self.http_flows[key] = (seqno, pkt_dir,'','', 0)
            return True

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

    def packet_matches_rule(self,pkt,pkt_dir,rule,country):
        pkt_protocol=struct.unpack('!B',pkt[9:10])[0]
        ipid=struct.unpack('!H',pkt[4:6])               #TODO: Do we need this?
        rule_protocol=rule[1]
        udp_pkt = self.strip_ip(pkt)
        dns_proto = rule_protocol=="dns"
        if dns_proto:
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

    def strip_tcpip(self,pkt):
        tcp_pkt = self.strip_ip(pkt)
        tcp_header_len = (struct.unpack('!B',pkt[12])[0]&0xF0)*4
        return tcp_pkt[tcp_header_len:]

    def should_ignore_packet(self,pkt):
        protocol=struct.unpack('!B',pkt[9:10])[0]
        if protocol!=17 and protocol!=6 and protocol!=1:
            return True
        else:
            return False


# TODO: You may want to add more classes/functions as well.
