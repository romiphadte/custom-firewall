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
        rules=[rule for rule in rules if len(rule) > 0 and (rule[0]=="deny" or rule[0]=="log" or rule[0]=="pass" or rule[0]=="drop")]
        rules=rules[::-1]
        self.log_rules=[rule for rule in rules if len(rule) >= 3 and rule[0] == "log" and rule[1] == "http"]
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
        self.pdbinterval = 3

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
            self.ip_checksum(pkt) 
            
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
                elif rule[0]=="deny" and rule[1]=="dns":
                    print "Deny accoring to rule:", rule, self.eval_pkt(pkt)
                    self.send_dns_response(pkt,pkt_dir)
                elif rule[0]=="deny" and rule[1]=="tcp":
                    print "Deny accoring to rule:", rule, self.eval_pkt(pkt)
                    self.send_tcp_response(pkt,pkt_dir)
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

    def write_http(self, key, pkt_dir):
        print "write http!"
        val = self.http_flows[key]
        logfile = open('http.log', 'a')
        split_req = val[2].split()
        h_match = re.search('Host:\s+(?P<hostname>\S+)', val[2])
        if h_match:
            host_name = h_match.group('hostname')
            if type(host_name) == tuple:
                host_name = host_name[0]
        else:
            host_name = key[1]
        method = split_req[0]
        path = split_req[1]
        version = split_req[2]
        status_code = val[3].split()[1]
        os_match = re.search('Content-Length:\s+(?P<objsize>\w+)', val[3])
        if os_match:
            object_size = os_match.group('objsize')
            if type(object_size) == tuple:
                object_size = object_size[0]
        else:
            object_size = '-1'
        log = "%s %s %s %s %s %s" % (host_name, method, path, version, status_code, object_size)
        for rule in self.log_rules:
            if self.log_rule_matches(host_name, rule, pkt_dir):
                print "log rule matches!"
                logfile.write(log)
                logfile.flush()
                break
        flow = self.http_flows[key]
        self.http_flows[key] = (flow[0], flow[1], '', '', flow[4])

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
                if pkt_dir == val[1]:
                    out_data = val[2] + http_pkt
                    new_pkt_dir = pkt_dir
                    #self.counter += 1
                    #if self.counter % self.pdbinterval == 0:
                    #    pdb.set_trace()
                    if re.search("\r\n\r\n", out_data):
                        print "outgoing packet finished"
                        new_pkt_dir = PKT_DIR_INCOMING
                    self.http_flows[key] = (seqno + len(http_pkt), new_pkt_dir, out_data, val[3], val[4])
                return True
            elif pkt_dir == PKT_DIR_INCOMING and ackno == val[0]:
                if pkt_dir == val[1]:
                    write = False
                    in_data = val[3] + http_pkt
                    new_pkt_dir = pkt_dir
                    #self.counter += 1
                    #if self.counter % self.pdbinterval == 0:
                    #    pdb.set_trace()
                    if re.search("\r\n\r\n", in_data):
                        new_pkt_dir = PKT_DIR_OUTGOING
                        write = True
                    self.http_flows[key] = (ackno + len(http_pkt), new_pkt_dir, val[2], in_data, val[4])
                    if write:
                        self.write_http(key, pkt_dir)
                return True
            elif pkt_dir == PKT_DIR_OUTGOING and val[0] > seqno:
                return True
            elif pkt_dir == PKT_DIR_INCOMING and val[0] > ackno:
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

    def read_question(self, dns_pkt):
        next_len = 12
        length = struct.unpack('!B', dns_pkt[next_len])[0]
        while length != 0:
            next_len += length + 1
            length = struct.unpack('!B', dns_pkt[next_len])[0]
        return dns_pkt[12:next_len + 1 + 4]

    def send_dns_response(self, pkt, pkt_dir):
        #pkt=self.swap_ip(pkt)
        udp_pkt = self.strip_ip(pkt)
        dns_pkt = udp_pkt[8:]
        question = self.read_question(dns_pkt)
        answer = question[:-4] + struct.pack('!H', 1) #name + type
        answer += struct.pack('!H', 1) + struct.pack('!L', 1) + struct.pack('!H', 4) #class+ttl+rlen
        answer += struct.pack('!BBBB', 54,173,224,150)

        dns_header = dns_pkt[0:2] + struct.pack('!BB',0b10000001,0x80)+ struct.pack('!HHHH', 0x1,0x1,0x0,0x0)
        dns_header += question + answer
        udp_header = "%s%s%s%s" % (udp_pkt[2:4],udp_pkt[0:2],struct.pack('!H',8+len(dns_header)),struct.pack('!H',0))
        udp_header += dns_header
        
        ip_header_len=(struct.unpack('!B',pkt[0:1])[0]&0xF)*4
        ip_header=self.swap_ip(pkt)[:ip_header_len]+udp_header
        length=struct.pack('!H',len(ip_header))
        ip_header=ip_header[:2]+length+ip_header[4:]

        ip_header=self.udp_checksum(ip_header)
        new_pkt=self.ip_checksum(ip_header)
        self.send_deny_pkt(new_pkt, pkt_dir)

    def send_tcp_response(self,pkt,pkt_dir):
        print "tcp deny"
        pkt=self.swap_ip(pkt)
        tcp_pkt=self.strip_ip(pkt)
        new_seq=struct.pack('!I',0)#struct.unpack('!L',tcp_pkt[8:12])[0]) 
        new_ack=struct.pack('!I',struct.unpack('!L',tcp_pkt[4:8])[0]+1)
        new_tcp_pkt=tcp_pkt[2:4]+tcp_pkt[0:2]+new_seq+new_ack+struct.pack('!B',0b01010000)+struct.pack('!B',0b00010100)+struct.pack('!HHH',0,0,0)

        ip_header_len=(struct.unpack('!B',pkt[0:1])[0]&0xF)*4
        new_pkt=pkt[:ip_header_len] + new_tcp_pkt
        new_pkt=self.tcp_checksum(new_pkt)
        self.send_deny_pkt(new_pkt,pkt_dir)
        print "tcp deny"

    def swap_ip(self,pkt):
        ttl=struct.pack('!B',64)
        checksum=struct.pack('!H',0)   #originally zero
        pkt[:6]+struct.pack('!B', 0x40)
        new_pkt=pkt[:8]+ttl+pkt[9]+checksum+pkt[16:20]+pkt[12:16]+pkt[20:]
        new_pkt=self.ip_checksum(new_pkt)
        return new_pkt 

    def udp_checksum(self,pkt):
        ip_header_len=(struct.unpack('!B',pkt[0:1])[0]&0xF)*4
        ip_header=pkt[:ip_header_len]
        udp_pkt=self.strip_ip(pkt)
        old=struct.unpack('!H',udp_pkt[6:8])[0]
        udp_pkt=udp_pkt[0:6]+struct.pack('!H',0)+udp_pkt[8:]
        #checksum=struct.pack('!H',self.checksum(pkt[12:16]+pkt[16:20]+struct.pack('!B',0)+pkt[9:10]+struct.pack('!H',len(udp_pkt))+udp_pkt))
        checksum=struct.pack('!H',0)
        new=struct.unpack('!H',checksum)
        if old!=new:
            print "diff"
        return ip_header+udp_pkt[0:6]+checksum+udp_pkt[8:]

    def ip_checksum(self,pkt):
        ip_header_len=(struct.unpack('!B',pkt[0:1])[0]&0xF)*4
        ip_header=pkt[:ip_header_len] 
        old=struct.unpack('!H',ip_header[10:12])[0]
        ip_header=ip_header[:10]+struct.pack('!H',0)+ip_header[12:]
        new=self.checksum(ip_header)
        if old!=new:
            print "diff"
        new_ip_header=ip_header[:10]+struct.pack('!H',self.checksum(ip_header))+ip_header[12:]
        return new_ip_header+pkt[ip_header_len:] 

    def tcp_checksum(self,pkt):
        ip_header_len=(struct.unpack('!B',pkt[0:1])[0]&0xF)*4
        ip_header=pkt[:ip_header_len] 
        tcp_pkt=self.strip_ip(pkt)
        old=struct.unpack('!H',tcp_pkt[16:18])[0]
        tcp_pkt=tcp_pkt[:16]+struct.pack('!H',0)+tcp_pkt[18:]
        entire=tcp_pkt+ip_header[12:16]+ip_header[16:20]+struct.pack('!H', 6)+struct.pack('!H',len(tcp_pkt))
        new=self.checksum(entire)
        if old!=new:
            print "diff", old, new, len(tcp_pkt), 
        else:
            print "same"
        new_tcp=tcp_pkt[:16]+struct.pack('!H',self.checksum(entire))+tcp_pkt[18:]
        return ip_header+new_tcp
         

    def checksum(self,s):
        total=0
        for i in xrange(len(s)/2):
            total=total+struct.unpack('!H',s[i*2:(i+1)*2])[0]
        if len(s)%2==1:
            total=total+(struct.unpack('!B',s[-1])[0]<<8)

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

    def strip_tcpip(self,pkt):
        tcp_pkt = self.strip_ip(pkt)
        tcp_header_len = ((struct.unpack('!B',tcp_pkt[12])[0]&0xF0)>>4)*4
        return tcp_pkt[tcp_header_len:]

    def should_ignore_packet(self,pkt):
        protocol=struct.unpack('!B',pkt[9:10])[0]
        if protocol!=17 and protocol!=6 and protocol!=1:
            return True
        else:
            return False


# TODO: You may want to add more classes/functions as well.
