import sys
import traceback
from tcpheader import TCPHeader
from socket import *

MSS = 576

LISTEN_STATE = 'LISTEN'
SYN_RCVD_STATE = 'SYN_RCVD'
ESTABLISHED_STATE = 'ESTABLISHED'
CLOSE_WAIT_STATE = 'CLOSE_WAIT'
LAST_ACK_STATE = 'LAST_ACK'

class Server(object):

    def __init__(self, listening_port, client_ip_address, client_port, output_file):
        self.buffer = []  # stack
        self.listening_port = listening_port # UDP listening port
        self.server_socket = socket(AF_INET, SOCK_DGRAM)
        self.server_socket.bind(('', int(self.listening_port)))
        self.client_ip_address = client_ip_address  # IP address to send ACKs to
        self.client_port = client_port  # port to send ACKs
        self.output_file = output_file # file to write the received data to
        self.header = TCPHeader(self.listening_port, self.client_port)
        self.state = LISTEN_STATE

    def listen(self):
        # listen continuously on listening port for connections from clients
        while True:
            message, client_address = self.server_socket.recvfrom(2048)
            message_string = message.decode()
            message_header = message_string[:161]
            message_payload = message_string[161:]

            # If SYN bit = 1, it is a 3-way handshake initiation
            if message_header[110] == 1 and self.state == LISTEN_STATE:
                self.tcp_header.set_syn(1)
                self.tcp_header.set_seq_number(random.randrange(2 ** 32 - 1))
                client_seq_num = message_header[:32]  # bits 0 to 31 in the header are the bits corresponding to the sequence number
                self.tcp_header.set_ack_num(int(client_seq_num) + 1)  # set ACK number as client's sequence number + 1
                tcp_header_bin_string = self.tcp_header.get_binary_string()
                message = tcp_header_bin_string.encode()

                # Send ACK directly to client
                self.client_socket.sendto(message, (self.client_ip_address, int(self.client_port)))
                self.state = SYN_RCVD_STATE
            elif message_header[110] == 0 and self.state == SYN_RCVD_STATE:
                self.state = ESTABLISHED_STATE
            elif message_header[110] == 0 and self.state == ESTABLISHED_STATE:
                client_seq_num = message_header[:32]
                self.tcp_header.set_seq_number()
            elif message_header[96] == 1: # FIN bit set
                pass

if __name__ == '__main__':
    try:
        output_file = sys.argv[1]
        listening_port = sys.argv[2]
        ip_address_for_acks = sys.argv[3]
        port_for_acks = sys.argv[4]

        if int(listening_port) < 1024 or int(listening_port) > 65535:
            raise ValueError("[Listening port number specified is invalid]")

        if int(port_for_acks) < 1024 or int(port_for_acks) > 65535:
            raise ValueError("[ACK port number specified is invalid]")

        if re.search("^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$", ip_address_for_acks) is None:
            sys.exit("[Invalid IP address for ACKs specified]")

        server = Server(listening_port, ip_address_for_acks, port_for_acks, output_file)
        server.listen()
    except Exception as e:
        print(f">>> [Invalid arguments]: {e}")
        traceback.print_exc()
        sys.exit(">>> [Exiting]")

