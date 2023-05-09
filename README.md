# TCP_Implementation
TCP Implementation over a UDP proxy

Command to run UDPL proxy:
```
./newudpl -p 2222:3333 -i 127.0.0.1:1234 -o 127.0.0.1:4444 -vv -L 0
```

Order of commands to run:
1. UDPL
2. TCP server
3. TCP client

List of files:
**1. tcpserver.py:**

Command to run:
```
python tcpserver.py result.txt 4444 127.0.0.1 8888
```

Description:
Contains the implementation of the TCP server

**2. tcpclient.py:**

Command to run:
```
python tcpclient.py input.txt 127.0.0.1 2222 1563 8888
```

Description:
Contains the implementation of the TCP client

**3. tcpheader.py:**

Description:
Contains the implementation of the TCP header, used by the TCP server and client