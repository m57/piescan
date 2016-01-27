#!/usr/bin/env python2

import sys
import socket
import shutil
import datetime
import threading

VERSION		= open("VERSION", "r").read().strip()
timeout 	= 3
VERBOSE 	= False
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
    print "\t-t [target ip]"
    print "\t-p [port] \t\t\te.g. ( -p 25 // -p 22,23,24,25 // -p 0-1024 )"
    print "\t-v \t\t\t\tVerbose output"
    print "\t--timeout [timeout in ms]"
    print ""

def print_results(target):

    print '{:<12} {:<12} {:<12}'.format("Port", "State", "Reason")
    print "-----------------------------------------------------"

    for p in open_ports:
        reason = "syn-ack"
	msg = "open"
        print '{:<12} {:<12} {:<12}'.format("%d/tcp" % p, msg, reason)
    
    if (len(closed_ports) < 15):
        for p in closed_ports:
            reason = "rst"
	    msg = "closed"
	    print '{:<12} {:<12} {:<12}'.format("%d/tcp" % p, msg, reason)
    else:
        port_states.append(get_states("closed", len(closed_ports)))
    
    if (len(filtered_ports) < 15):
        for p in filtered_ports:
            reason = "timeout"
	    msg = "filtered"
            print '{:<12} {:<12} {:<12}'.format("%d/tcp" % p, msg, reason)
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

    for p in ports:
	t = threading.Thread(target = tcp_scan, args = (target, p))
        t.start()

    print_results(target)
    print ""

    for p in port_states:
	print p
    print ""

    print "[ %s ] Scan finished.\n" % (datetime.datetime.now().strftime("%H:%M:%S - %d/%m/%Y")) 
