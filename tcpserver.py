import sys
import time
import traceback
from tcpheader import TCPHeader
from socket import *
import re

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
        self.current_ack_num = 0  # Max ACK number sent so far
        self.process_message_flag = False
        # stores the string message for each sequence number so that we can reorder before writing to the file at the end
        self.seq_num_to_chunk = {}

    def listen(self):
        # listen continuously on listening port for connections from clients
        while True:
            message, client_address = self.server_socket.recvfrom(2048)

            self.buffer.append(message)
            process_messages_thread = Thread(target=self.process_messages, args=(), daemon=True)
            process_messages_thread.start()
            self.process_message_flag = True
            if len(buffer) == 0:
                self.process_message_flag = False
            process_messages_thread.join()
            return

    def process_messages(self):
        while self.process_message_flag:
            if len(buffer) == 0:
                return
            message = buffer.pop()

            message_string = message.decode()
            message_header = message_string[:161]
            message_payload = message_string[161:]
            checksum_received = header[128:160]
            self.calculate_checksum(message)

            if not self.validate_checksum(checksum_received):
                # If SYN bit = 1, it is a 3-way handshake initiation
                if message_header[110] == 1 and self.state == LISTEN_STATE:
                    print("[Received SYN handshake message]")
                    self.tcp_header.set_syn(1)
                    self.tcp_header.set_seq_number(random.randrange(2 ** 32 - 1))
                    client_seq_num = message_header[:32]  # bits 0 to 31 in the header are the bits corresponding to the sequence number
                    self.current_ack_num = int(client_seq_num) + 1
                    self.tcp_header.set_ack_num(self.current_ack_num)  # set ACK number as client's sequence number + 1
                    message = self.tcp_header.get_binary_string().encode()

                    # Send ACK directly to client
                    self.client_socket.sendto(message, (self.client_ip_address, int(self.client_port)))
                    print("[Sent SYNACK message]")
                    self.state = SYN_RCVD_STATE
                elif message_header[110] == 0 and self.state == SYN_RCVD_STATE:
                    print("[Received final ACK, connection established]")
                    self.state = ESTABLISHED_STATE

                elif message_header[110] == 0 and self.state == ESTABLISHED_STATE:
                    # If the sequence number of the message received from client > current ACK number, resend current ACK number
                    # elif < : do nothing because implies that it has already been ACKED,
                    # else = : update ACK number since the next expected sequence number broadcasted in prev message has been received)
                    # reset current ACK number as sequence number + length of payload
                    # Set sequence number for which it is the ACK
                    # Write to output file data
                    client_seq_num_bin = message_header[:32]
                    client_seq_num_int = int(client_seq_num_bin, 2)
                    # if sequence number of message received < max ACK number sent, we don't want to do anything
                    # because it has already been cumulatively ACK-ed
                    print(f"[Received sequence number {client_seq_num_int}]")
                    if client_seq_num_int == self.current_ack_num:
                        # We keep recording the output file data and write it at once on connection close
                        self.seq_num_to_chunk[client_seq_num_int] = message_payload
                        self.current_ack_num += len(message_payload.encode())
                        self.tcp_header.set_ack_num(self.current_ack_num)
                        self.tcp_header.set_seq_number(client_seq_num_int)
                        self.client_socket.sendto(message, (self.client_ip_address, int(self.client_port)))
                        print(f"[Packet accepted. Ready to receive next sequence number {self.current_ack_num}, ACK sent]")
                    elif client_seq_num_int > self.current_ack_num:  # Gap detected, resend ACK
                        self.tcp_header.set_ack_num(self.current_ack_num)
                        self.tcp_header.set_seq_number(client_seq_num_int)
                        self.client_socket.sendto(message, (self.client_ip_address, int(self.client_port)))
                        print(f"[Gap detected, ACK for sequence number {client_seq_num_int} received, when last ACK sent was for sequence number {self.current_ack_num}]")

                # Received message with FIN bit set
                elif message_header[96] == 1 and self.state == ESTABLISHED_STATE:
                    print("[Received connection close request (FIN handshake message)]")
                    with open(self.output_file, 'w') as file:
                        sorted_seq_num_to_chunk = dict(sorted(self.seq_num_to_chunk.items()))
                        data = ''
                        for seq_num in sorted_seq_num_to_chunk.keys():
                            data += sorted_seq_num_to_chunk[seq_num]
                        file.write(data)
                        file.close()
                    print(f"[Finished writing to output file {self.output_file}]")
                    message = self.tcp_header.get_binary_string().encode()
                    self.client_socket.sendto(message, (self.client_ip_address, int(self.client_port)))
                    print("[Sent FINACK handshake message]")
                    self.state = CLOSE_WAIT_STATE
                    time.sleep(10)
                    self.tcp_header.set_fin(1)
                    message = self.tcp_header.get_binary_string().encode()
                    self.client_socket.sendto(message, (self.client_ip_address, int(self.client_port)))
                    print("[Sent final FIN handshake message]")
                    self.state = LAST_ACK_STATE
                elif message_header[96] == 0 and self.state == LAST_ACK_STATE:
                    self.state = LISTEN_STATE
                    print("[Connection closed]")

    def calculate_checksum(self, message):
        self.tcp_header.reset_checksum()
        for i in range(0, len(message.encode()) * 8, 16):
            chunk = message.encode()[i:i + 16]
            self.tcp_header.checksum[0].set_checksum(self.tcp_header.checksum[0] ^ chunk)
        print("[Checksum computed]")

    def validate_checksum(self, checksum):
        if checksum != header[128:160]:
            return False
        return True


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
        print(f"[Invalid arguments]: {e}")
        traceback.print_exc()
        sys.exit("[Exiting]")

