#!/usr/bin/env python2

import sys
import socket
import shutil
import datetime
import threading

VERSION		= open("VERSION", "r").read().strip()
VERBOSE 	= False
SCAN_TYPE	= "TCP"
timeout 	= 5

#sema		= Semaphore(value=1)

open_ports 	= []
filtered_ports 	= []
closed_ports	= []

port_states 	= []

def banner():

	print ""
	print "\t  %spiescan v%s%s -- %shttps://www.twitter.com/@_x90__%s" % ("\033[1;32m", VERSION, "\033[0m", "\033[1;31m", "\033[0m")
	print "\t---------------------------------------------------"
	print ""
	print "\t\t A simple port scanner"
	print ""

def date_time():
    return datetime.datetime.now().strftime("%H:%M:%S")

def tcp_scan(target, port):

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(timeout)
	        
        ret = conn.connect_ex((target, port))

        if (ret==0):
            if VERBOSE:
                print "[%s] %s - %d/tcp open (SYN-ACK packet)" % (date_time(), target, port)
            open_ports.append(port)
	elif (ret == 111):
            if VERBOSE:
                print "[%s] %s - %d/tcp closed (RST packet)" % (date_time(), target, port)
            closed_ports.append(port)
	elif (ret == 11):
	    filtered_ports.append(port)
 	            
    except socket.timeout:
        filtered_ports.append(port)
        
    conn.close()

def udp_scan(target, port):

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.settimeout(timeout)
	
        datas = {
		"piescan" 	: b"\x70\x69\x65\x73\x63\x61\x6e\x6e\x65\x72\x20\x2d\x20\x40\x5f\x78\x39\x30\x5f\x5f",
		"dns"		: b"\x24\x1a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
		"snmp"		: b"\x30\x2c\x02\x01\x00\x04\x07\x70\x75\x62\x6c\x69\x63\xA0\x1E\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x13\x30\x11\x06\x0D\x2B\x06\x01\x04\x01\x94\x78\x01\x02\x07\x03\x02\x00\x05\x00",
		"ntp"		: b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1x\52\xf3" 
	}

    	if (port == 123): 
		conn.sendto(datas["ntp"], (target,port))
		r = conn.recv(1024)

	elif (port == 53):
		conn.sendto(datas["dns"], (target,port))
		r = conn.recv(1024)

    	elif (port == 161):
		conn.sendto(datas["snmp"], (target,port))
		r = conn.recv(1024)

    	else:
		conn.sendto(datas["piescan"], (target,port))
		r = conn.recv(1024)
		open_ports.append(port)

    except socket.ConnectionRefusedError:
        closed_ports.append(port)

    except socket.timeout:
        filtered_ports.append(port)
        
    conn.close()

def parse_ports(arg):

    ports = []

    if "-" in arg:
        try:
            start,end = arg.split("-")
            start = int(start)
            end = int(end)
            if (start <= 65535) and (end <= 65535):
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

    print '{:<12} {:<12} {:<12}'.format("Port", "State", "Reason")
    print "-----------------------------------------------------"

    for p in open_ports:
        reason = "syn-ack"
	msg = "open"
        print '{:<12} {:<12} {:<12}'.format("%d/%s" % (p, SCAN_TYPE.lower()), msg, reason)
    
    if (len(closed_ports) < 15):
        for p in closed_ports:
            reason = "rst"
	    msg = "closed"
	    print '{:<12} {:<12} {:<12}'.format("%d/%s" % (p, SCAN_TYPE.lower()), msg, reason)
    else:
        port_states.append(get_states("closed", len(closed_ports)))
    
    if (len(filtered_ports) < 15):
        for p in filtered_ports:
            reason = "timeout"
	    msg = "filtered"
            print '{:<12} {:<12} {:<12}'.format("%d/%s" % (p, SCAN_TYPE.lower()),  msg, reason)
    else:
        port_states.append(get_states("filtered", len(filtered_ports)))

def get_states(msg, n):

	return "%d %s ports." % (n, msg)

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
    
    print "[ %s ] Scan started - Host: %s\n" % (datetime.datetime.now().strftime("%H:%M:%S - %d/%m/%Y"), target) 

    if SCAN_TYPE == "TCP":
        for p in ports:
	    t = threading.Thread(target = tcp_scan, args = (target, p))
       	    t.start()
    elif SCAN_TYPE == "UDP":
        for p in ports:
             t = threading.Thread(target = udp_scan, args = (target, p))
             t.start()
    else:
        usage() # is this even possible ?
	exit(1)

    print_results(target)
    print ""

    for p in port_states:
	print p
    print ""

    print "[ %s ] Scan finished.\n" % (datetime.datetime.now().strftime("%H:%M:%S - %d/%m/%Y")) 
