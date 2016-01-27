# piescan

A really simple port scanner, for times when you cant use nmap.

# Usage

root@ip # ./piescan.py 

          piescan v1.0 -- https://www.twitter.com/@_x90__
        ---------------------------------------------------

                    A simple port scanner

          Usage: ./piescan.py -t [targets] -p [ports] [options]

          Options:

        -t [target ip]
        -p [port]                       e.g. ( -p 25 // -p 22,23,24,25 // -p 0-1024 )
        -v                              Verbose output
        --timeout [timeout in ms]

