# TCP_Implementation
TCP Implementation over a UDP proxy or emulator which simulates a network mimicking congestion, corruption of bits, delay and packet loss based on percentage specified. (Not included in this repository since it is proprietary)

Command to run UDPL proxy:
It is of the form `newudpl -p receive_port:send_port -i input_host_address -o output_host_address -L loss-percentage`. 1234 has been hard coded/configured in the TCP client code as the sending port.

```
./newudpl -p 2222:3333 -i 127.0.0.1:1234 -o 127.0.0.1:4444 -vv -L 50
```

Order of commands to run:
1. UDPL
2. TCP server
3. TCP client

List of files:
**1. tcpserver.py:**

Command to run:
It is of the form `tcpserver file listening_port address_for_acks port_for_acks` where file is the input file from which data is to be read

```
python tcpserver.py result.txt 4444 127.0.0.1 8888
```

Description:
Contains the implementation of the TCP server

**2. tcpclient.py:**

Command to run:
It is of the form `tcpclient file address_of_udpl port_number_of_udpl windowsize ack_port_number` where file is the output file to which serve writes. The window size is measured in bytes.

```
python tcpclient.py input.txt 127.0.0.1 2222 1563 8888
```

Description:
Contains the implementation of the TCP client

**3. tcpheader.py:**

Description:
Contains the implementation of the 20-byte TCP header, used by the TCP server and client without implementing push (PSH flag), urgent data (URG), reset (RST), or TCP options.
