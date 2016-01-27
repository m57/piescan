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

# Example Output

root@x250-arch:[piescan] # ./piescan.py -t 127.0.0.1 -p 0-65535                                                                                                                                                    

          piescan v1.0 -- https://www.twitter.com/@_x90__
        ---------------------------------------------------

                 A simple port scanner

          [ 22:23:43 - 27/01/2016 ] Scan started - Host: 127.0.0.1

          Port         State        Reason      
          -----------------------------------------------------
          22/tcp       open         syn-ack     
          6340/tcp     open         syn-ack     
          24/tcp       filtered     timeout     

          65533 closed ports.

          [ 22:23:51 - 27/01/2016 ] Scan finished.
