# piescan

A really simple port scanner, for times when you cant use nmap.

# Usage

```root@ip # ./piescan.py 

          piescan v2.0 -- https://www.twitter.com/@_g0dmode
        ---------------------------------------------------
            A simple, fast, lightweight TCP/UDP scanner

Usage: piescan.py -t [targets] -p [ports] [options]

Options:

        -t         [target ip]
        -p         [port]                         Examples: ( -p 25 || -p 22,23,24,25 || -p 0-1024 )
        -s[TU]     Scan type ( default = -sT )    Examples: ( -sT : TCP || -sU : UDP )
        --threads  Number of threads (Default=10)
        -v         Verbose output
        --timeout  [timeout in ms]

Examples:

        piescan.py -sT -t 127.0.0.1 -p 0-65535 -v  - Do a verbose TCP scan of all ports on 127.0.0.1
        piescan.py -sU -t 127.0.0.1 -p 0-100       - Do a UDP scan of the first 100 ports on 127.0.0.1
```

# Example TCP scan of some specific ports

```
# piescan.py -t google.com -v -p 80,443,21,22

          piescan v2.0 -- https://www.twitter.com/@_g0dmode
        ---------------------------------------------------
            A simple, fast, lightweight TCP/UDP scanner

[28/06/2021 21:10:14] Scan started - Host: google.com (172.217.169.46)
[28/06/2021 21:10:14] 172.217.169.46 - 443/tcp open (SYN-ACK packet)
[28/06/2021 21:10:14] 172.217.169.46 - 80/tcp open (SYN-ACK packet)

Port            State           Reason
-----------------------------------------------------
22/tcp          filtered        timeout
21/tcp          filtered        timeout
443/tcp         open            syn-ack
80/tcp          open            syn-ack

[28/06/2021 21:10:19] Scan finished.
```

# Example UDP scan of top 1000 ports

```
# sudo python2 piescan.py -sU -t 1.uk.pool.ntp.org -v --timeout 500 --threads 20
[sudo] password for xxx:

          piescan v2.0 -- https://www.twitter.com/@_g0dmode
        ---------------------------------------------------
            A simple, fast, lightweight TCP/UDP scanner

[28/06/2021 21:13:44] Scan started - Host: 1.uk.pool.ntp.org (162.159.200.1)
[28/06/2021 21:13:45] 162.159.200.1 - 123/udp open (Data recieved)

Port            State           Reason
-----------------------------------------------------
123/udp         open            Data recieved
909 open|filtered ports.

[28/06/2021 21:14:07] Scan finished.
```