import sys
import time
import traceback
from tcpheader import TCPHeader
from socket import *
import re
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
import random

MSS = 576

LISTEN_STATE = 'LISTEN'
SYN_RCVD_STATE = 'SYN_RCVD'
ESTABLISHED_STATE = 'ESTABLISHED'
CLOSE_WAIT_STATE = 'CLOSE_WAIT'
LAST_ACK_STATE = 'LAST_ACK'

executor = ThreadPoolExecutor(max_workers=5)

class Server(object):

    def __init__(self, listening_port, client_ip_address, client_port, output_file):
        print(f"Server is up on {client_ip_address} on port {listening_port}")
        self.buffer = []  # stack
        self.listening_port = int(listening_port)  # UDP listening port
        self.server_socket = socket(AF_INET, SOCK_DGRAM)
        self.server_socket.bind(('127.0.0.1', int(self.listening_port)))
        self.client_ip_address = client_ip_address  # IP address to send ACKs to
        self.client_port = int(client_port)  # port to send ACKs
        self.output_file = output_file  # file to write the received data to
        self.tcp_header = TCPHeader(self.listening_port, self.client_port)
        self.state = LISTEN_STATE
        self.current_ack_num = 0  # Max ACK number sent so far
        # stores the string message for each sequence number so that we can reorder before writing to the file at the end
        self.seq_num_to_chunk = {}

    def listen(self):
        """
        Listen continuously on listening port for connections from clients
        """
        self.server_socket.settimeout(10)
        while True:
            try:
                if not self.server_socket.fileno() == -1:
                    message, client_address = self.server_socket.recvfrom(2048)

                    self.buffer.append(message)
                    thread = Thread(target=self.process_messages, daemon=True)
                    executor.submit(thread.start)
                else:
                    break
            except timeout:
                print("[No response from client, timing out]")
                self.server_socket.close()
                break
        sys.exit()

    def process_messages(self):
        """
        Process messages received based as long as the buffer is non-empty and checksum is valid.
        Messages received can be part of connection set up and teardown handshake messages.
        For data transmission, the methodology for processing is as follows:
        * If the sequence number of the message received from client = current ACK number, it is the expected sequence
        number. Reset current ACK number as sequence number + length of payload and send it to client as next expected
        sequence number. Set sequence number for which it is the ACK in this segment.
        * Else if the sequence number of the message received from client > current ACK number, resend current ACK number
    update ACK number since the next expected sequence number broadcasted in prev message has been received
        * If the sequence number of the message received from client < current ACK number, do nothing because it
        implies that it has already been ACKED cumulatively
        """
        while True:
            if len(self.buffer) > 0:
                message = self.buffer.pop()
                message_string = message.decode('utf-16')
                print("[Server received message]")
                message_header = message_string[:160]
                message_payload = message_string[160:]
                checksum_received = int(message_header[128:144], 2)

                if self.validate_checksum(checksum_received, message_string):
                    # If SYN bit = 1, it is a 3-way handshake initiation
                    if int(message_header[110]) == 1 and self.state == LISTEN_STATE:
                        print("[Received SYN handshake message]")
                        self.tcp_header.set_syn(1)
                        self.tcp_header.set_seq_num(random.randrange(2 ** 32 - 1))
                        client_seq_num = message_header[32:64]  # bits 32 to 64 in the header are the bits corresponding to the sequence number

                        self.current_ack_num = int(client_seq_num, 2) + 1
                        self.tcp_header.set_ack_num(self.current_ack_num)  # set ACK number as client's sequence number + 1
                        message = self.tcp_header.get_binary_string().encode('utf-16')

                        # Send ACK directly to client
                        self.server_socket.sendto(message, (self.client_ip_address, self.client_port))
                        print(f"[Sent SYNACK message to {(self.client_ip_address, self.client_port)}]")
                        self.state = SYN_RCVD_STATE
                    elif int(message_header[110]) == 0 and self.state == SYN_RCVD_STATE:
                        print("[Received final ACK, connection established]")
                        self.state = ESTABLISHED_STATE

                    # Received message with FIN bit set
                    elif int(message_header[111]) == 1 and self.state == ESTABLISHED_STATE:
                        print("[Received connection close request (FIN handshake message)]")
                        with open(self.output_file, 'wb') as file:
                            sorted_seq_num_to_chunk = dict(sorted(self.seq_num_to_chunk.items()))
                            data = ''
                            for seq_num in sorted_seq_num_to_chunk.keys():
                                data += sorted_seq_num_to_chunk[seq_num]
                            file.write(data.encode('utf-16'))
                            file.close()
                        print(f"[Finished writing to output file {self.output_file}]")
                        message = self.tcp_header.get_binary_string().encode('utf-16')
                        self.server_socket.sendto(message, (self.client_ip_address, self.client_port))
                        print("[Sent FINACK handshake message]")
                        self.state = CLOSE_WAIT_STATE
                        time.sleep(3)
                        self.tcp_header.set_fin(1)
                        message = self.tcp_header.get_binary_string().encode('utf-16')
                        self.server_socket.sendto(message, (self.client_ip_address, self.client_port))
                        print("[Sent final FIN handshake message]")
                        self.state = LAST_ACK_STATE

                    elif int(message_header[111]) == 0 and self.state == LAST_ACK_STATE:
                        self.state = LISTEN_STATE
                        print("[Connection closed]")
                        self.server_socket.close()
                        break

                    elif int(message_header[110]) == 0 and self.state == ESTABLISHED_STATE:
                        client_seq_num_bin = message_header[32:64]
                        client_seq_num_int = int(client_seq_num_bin, 2)
                        print(f"[Received sequence number {client_seq_num_int}]")
                        if client_seq_num_int == self.current_ack_num:
                            # We keep recording the output file data and write it at once on connection close
                            self.seq_num_to_chunk[client_seq_num_int] = message_payload
                            self.current_ack_num += len(message_payload.encode('utf-16'))
                            self.tcp_header.set_ack_num(self.current_ack_num)
                            self.tcp_header.set_seq_num(client_seq_num_int)
                            message = self.tcp_header.get_binary_string().encode('utf-16')
                            self.server_socket.sendto(message, (self.client_ip_address, self.client_port))
                            print(f"[Packet accepted. Ready to receive next sequence number {self.current_ack_num}, ACK sent to {(self.client_ip_address, self.client_port)}]")
                        elif client_seq_num_int > self.current_ack_num:  # Gap detected, resend ACK
                            self.tcp_header.set_ack_num(self.current_ack_num)
                            self.tcp_header.set_seq_num(client_seq_num_int)
                            message = self.tcp_header.get_binary_string().encode('utf-16')
                            self.server_socket.sendto(message, (self.client_ip_address, self.client_port))
                            print(f"[Gap detected, ACK for sequence number {client_seq_num_int} received, when last ACK sent was for sequence number {self.current_ack_num}]")

    def calculate_checksum(self, message):
        """
        Calculates the checksum using traditional TCP method
        :param message: UTF-16 encoded message including payload and header
        :return: Calculated checksum
        """
        checksum = 0
        for i in range(0, len(message) - 1, 2):
            current = (message[i] << 8) + message[i + 1]
            checksum = checksum + current
            checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = ~checksum & 0xffff
        return checksum

    def validate_checksum(self, received_checksum, message):
        """
        Compares computed checksum and the checksum in the checksum field of the received TCP header.
        Returns True if the values are equal, else returns False
        :param received_checksum: Checksum in the checksum field of the received message's TCP header
        :param message: The entire received message including payload and TCP header
        :return: True or False
        """
        message_no_checksum = message[:128] + format(0, 'b').zfill(16) + message[144:]
        binary_string = message_no_checksum.encode('utf-16')
        computed_checksum = self.calculate_checksum(binary_string)
        if received_checksum != computed_checksum:
            print("[Checksum received: " + str(received_checksum) + "]")
            print("[Checksum computed: " + str(computed_checksum) + "]")
            print("[Checksum invalid]")
            return False
        print("[Checksum valid]")
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

