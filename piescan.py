#!/usr/bin/env python2

import os
import sys
import time
import ctypes
import struct
import socket
import shutil
import datetime
import threading
import Queue

UDP_sig 	= {
			"piescan" 	: b"\xff\xff\x70\x69\x65\x73\x63\x61\x6e\x6e\x65\x72\x20\x2d\x20\x40\x5f\x78\x39\x30\x5f\x5f",
			"dns"		: b"\x24\x1a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
			"snmp"		: b"\x30\x2c\x02\x01\x00\x04\x07\x70\x75\x62\x6c\x69\x63\xA0\x1E\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x13\x30\x11\x06\x0D\x2B\x06\x01\x04\x01\x94\x78\x01\x02\x07\x03\x02\x00\x05\x00",
			"ntp"		: b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3" 
			}

ports_ident	= { 
			"open" 		: [],
			"closed" 	: [],
			"filtered"	: [],
			"open|filtered"	: []	 
			}

try:
	VERSION		= open("VERSION", "r").read().strip()
except:
	VERSION		= "unknown"
	print "'VERSION' file not found, please re-clone : https://www.github.com/m57/piescan.git"

VERBOSE 	= False
SCAN_TYPE	= "TCP"
SNIFF_MUTEX	= 1
timeout 	= 5
port_states 	= []

class ICMP(ctypes.Structure):
    _fields_ = [
    ('type',        ctypes.c_ubyte),
    ('code',        ctypes.c_ubyte),
    ('checksum',    ctypes.c_ushort),
    ('unused',      ctypes.c_ushort),
    ('next_hop_mtu',ctypes.c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass


def banner():

	print ""
	print "\t  %spiescan v%s%s -- %shttps://www.twitter.com/@_x90__%s" % ("\033[1;32m", VERSION, "\033[0m", "\033[1;31m", "\033[0m")
	print "\t---------------------------------------------------"
	print "\t    A simple, fast, lightweight TCP/UDP scanner"
	print ""

def date_time():
    return datetime.datetime.now().strftime("%H:%M:%S")

def tcp_scan((target, port)):

    target, port = (target, port)

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1,0))
        conn.settimeout(timeout)

        ret = conn.connect_ex((target, port))

	# DATA RECIEVED - SYN ACK
        if (ret==0):
            if VERBOSE:
                print "[%s] %s - %d/tcp open (SYN-ACK packet)" % (date_time(), target, port)
            ports_ident["open"].append(port)
	
	# RST RECIEVED - PORT CLOSED
	elif (ret == 111):
            if VERBOSE:
                print "[%s] %s - %d/tcp closed (RST packet)" % (date_time(), target, port)
            ports_ident["closed"].append(port)
	
	# ERR CODE 11 - TIMEOUT
	elif (ret == 11):
	   ports_ident["filtered"].append(port)
 	            
    except socket.timeout:
	ports_ident["filtered"].append(port)
        
    conn.close()

def udp_scan((target, port)):

    target, port = (str(target), int(port))

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.settimeout(timeout)
	
    	if (port == 123): 
		conn.sendto(UDP_sig["ntp"], (target,port))
	elif (port == 53):
		conn.sendto(UDP_sig["dns"], (target,port))
    	elif (port == 161):
		conn.sendto(UDP_sig["snmp"], (target,port))
    	else:
		conn.sendto(UDP_sig["piescan"], (target,port))

	d = conn.recv(1024)
	
	if (len(d) > 0):
		ports_ident["open"].append(port)
		
    except socket.timeout:
        ports_ident["open|filtered"].append(port)
        
    conn.close()

def parse_ports(arg):

    ports = []

    if "-" in arg:
        try:
            start,end = arg.split("-")
            start = int(start)
            end = int(end)
            if (start <= 65535) and (end <= 65535):
		if SCAN_TYPE == "UDP" and start == 0:
			start += 1

                for p in range(start,end+1):
                    ports.append(p)
            else:
                print "Ports cannot be higher than 65535"
                sys.exit(1)
        except:
            print "Error with port specification. e.g. (0-1000)"
            sys.exit(1)

    elif "," in arg:
        try:
            for p in arg.split(","):
                if (int(p) <= 65535):
                    ports.append(int(p))
                else:
                    print "Ports cannot be higher than 65535"
                    sys.exit(1)
        except:
            print "Error with port specification. e.g. (22,23,25)"
            sys.exit(1)

    else:
        try:
            if (int(arg) <= 65535):
                ports.append(int(arg))
            else:
                print "Ports cannot be higher than 65535"
                sys.exit(1)
        except:
                print "Error with port specified. See help."
                sys.exit(1)

    return ports

def parse_target(args):
    return args

def usage():

    banner()    
    print "Usage: %s -t [targets] -p [ports] [options]" % sys.argv[0]
    print ""
    print "Options:"
    print ""
    print "\t{:<10} {:<30}".format("-t", "[target ip]")
    print "\t{:<10} {:<30} {:<40}".format("-p", "[port]", "Examples: ( -p 25 || -p 22,23,24,25 || -p 0-1024 )")
    print "\t{:<10} {:<30} {:<40}".format("-s[TU]", "Scan type ( default = -sT )", "Examples: ( -sT : TCP || -sU : UDP )")
    print "\t{:<10} {:<30}".format("-v", "Verbose output")
    print "\t{:<10} {:<30}".format("--timeout", "[timeout in ms]", "(default=5s)")
    print ""
    print "Examples:"
    print "\n\t%s -sT -t 127.0.0.1 -p 0-65535 -v  - Do a verbose TCP scan of all ports on 127.0.0.1" % sys.argv[0]
    print "\t%s -sU -t 127.0.0.1 -p 0-100       - Do a UDP scan of the first 100 ports on 127.0.0.1" % sys.argv[0]	

    print ""

def print_results(target):

    print '{:<15} {:<15} {:<15}'.format("Port", "State", "Reason")
    print "-----------------------------------------------------"

    for state,p_list in ports_ident.iteritems():
	if ( len(p_list) > 20 ):
		port_states.append(get_states(state, len(p_list)))
	else:
		for port in p_list:
			
			if state == "open":
				if SCAN_TYPE == "UDP":
					print '{:<15} {:<15} {:<15}'.format("%d/%s" % (port, SCAN_TYPE.lower()), state, "Data recieved")
				else:
					print '{:<15} {:<15} {:<15}'.format("%d/%s" % (port, SCAN_TYPE.lower()), state, "syn-ack")
			elif state == "filtered":
					print '{:<15} {:<15} {:<15}'.format("%d/%s" % (port, SCAN_TYPE.lower()), state, "timeout")
			elif state == "open|filtered":
					print '{:<15} {:<15} {:<15}'.format("%d/%s" % (port, SCAN_TYPE.lower()), state, "timeout")
			elif state == "closed":
				if SCAN_TYPE == "UDP":
					print '{:<15} {:<15} {:<15}'.format("%d/%s" % (port, SCAN_TYPE.lower()), state, "ICMP Code 3")
				else:
					print '{:<15} {:<15} {:<15}'.format("%d/%s" % (port, SCAN_TYPE.lower()), state, "rst")
				
		
def get_states(msg, n):

	return "%d %s ports." % (n, msg)

def multi_threader_tcp():
	while True:
		ip_and_port = q.get()
		tcp_scan(ip_and_port)
		q.task_done()

def multi_threader_udp():
	while True:
		ip_and_port = q.get()
		udp_scan(ip_and_port)
		q.task_done()
		
def sniffer_thread(target):

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sniffer.bind(("0.0.0.0", 0 ))
    sniffer.settimeout(5)
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # continually read in packets and parse their information
    while ( 1 ):
	try:
	        raw_buffer = sniffer.recvfrom(65565)[0]
        
	except:
		if (SNIFF_MUTEX == 0):
			sys.exit(1)

	ip_header = raw_buffer[0:20]
	dst_port = struct.unpack(">h", raw_buffer[0x32:0x34])[0]
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

        # Create our IP structure
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        src_addr = socket.inet_ntoa(iph[8]);

        # Create our ICMP structure
        buf = raw_buffer[iph_length:iph_length + ctypes.sizeof(ICMP)]
        icmp_header = ICMP(buf)

        # check for the type 3 and code and within our target subnet
        if icmp_header.code == 3 and icmp_header.type == 3 and src_addr == target:
		if dst_port not in ports_ident["closed"]:
			ports_ident["closed"].append(dst_port)

if __name__ == "__main__":

    if "-v" in sys.argv:
        VERBOSE = True

    if "-h" in sys.argv or "--help" in sys.argv:
        usage()
        sys.exit(0)

    if "-sU" in sys.argv:
	SCAN_TYPE = "UDP"

    if "--timeout" in sys.argv:
        try:
            timeout = float(sys.argv[sys.argv.index("--timeout")+1])
        except:
            print "Error with supplied timeout value"
            sys.exit(1)

    if "-t" not in sys.argv or "-p" not in sys.argv:
        usage()
        sys.exit(1)

    banner()

    target  = parse_target(sys.argv[sys.argv.index("-t")+1])
    ports   = parse_ports(sys.argv[sys.argv.index("-p")+1])
    q	    = Queue.Queue()
    
    print "[ %s ] Scan started - Host: %s\n" % (datetime.datetime.now().strftime("%H:%M:%S - %d/%m/%Y"), target) 

    if SCAN_TYPE == "UDP":

	s_thread 	= threading.Thread(target=sniffer_thread, args=(target,))
	s_thread.start()


    for x in range(30):
    	if SCAN_TYPE == "TCP":
		t = threading.Thread(target=multi_threader_tcp)
	elif SCAN_TYPE == "UDP":
		t = threading.Thread(target=multi_threader_udp)
	t.daemon = True
	t.start()

    for p in ports:
	q.put((target,p))

    q.join()

    print_results(target)
    print ""

    for p in port_states:
	print p
    print ""

    print "[ %s ] Scan finished.\n" % (datetime.datetime.now().strftime("%H:%M:%S - %d/%m/%Y")) 

    SNIFF_MUTEX = 0
