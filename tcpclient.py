import socket
import sys
import time
import traceback
from tcpheader import TCPHeader
from socket import *
import re
import random
from threading import Thread, Event

MSS = 576
ALPHA = 0.125
BETA = 0.25
MAX_RETRIES = 3
MAX_TIMEOUT = 60

CLOSED_STATE = 'CLOSED'
SYN_SENT_STATE = 'SYN_SENT'
ESTABLISHED_STATE = 'ESTABLISHED'
FIN_WAIT_1_STATE = 'FIN_WAIT_1'
FIN_WAIT_2_STATE = 'FIN_WAIT_2'
TIME_WAIT_STATE = 'TIME_WAIT'

class Client(object):

    def __init__(self, source_port, udpl_port, input_file, udpl_ip_address, windowsize):
        self.buffer = []  # stack holding sequence numbers of all packets not in window
        self.tcp_header = TCPHeader(source_port, udpl_port)
        self.state = CLOSED_STATE
        self.input_file = input_file
        self.listening_port = int(source_port)  # port for listening for ACKs from server
        self.listening_socket = socket(AF_INET, SOCK_DGRAM)
        self.listening_socket.bind(('127.0.0.1', self.listening_port))
        self.source_port = 1234  # sending port
        print(f"[Client is up at 127.0.0.1, listening on {self.listening_port} and sending from {self.source_port}]")
        self.client_socket = socket(AF_INET, SOCK_DGRAM)
        self.client_socket.bind(('127.0.0.1', self.source_port))
        self.udpl_port = int(udpl_port)
        self.udpl_ip_address = udpl_ip_address
        self.windowsize = int(windowsize)  # specified in bytes
        self.window = []
        self.timeout_interval = 10  # Choosing an arbitrary initial timeout (for data transmission)
        self.sample_rtt = 0
        self.estimated_rtt = 0
        self.dev_rtt = 0
        self.ack_tracker = {}  # stores {sequence_number: no.of acks} received
        self.seq_num_to_chunk = {}  # stores sequence_number: TCP segment.
        self.seq_num_to_is_retransmitted = {}  # stores {sequence_number: is_retransmitted boolean flag}
        self.seq_num_to_transmit_time = {}  # storing the time each packet was transmitted for the first time, used to calculate sample RTT
        self.send_base = 0  # start of window, last sequence number that was sent but not ACKed
        self.next_seq_num = 0  # the next sequence number which needs to be resent
        self.last_seq_num = 0
        self.handshake_event = Event()  # exit event to kill retry timeout thread if ACK is received
        self.end_transmission = False

    def three_way_handshake(self):
        """
        Performs 3-way handshake and goes through the various states of the client in the process.
        Retries sending messages a total of MAX_RETRIES time if it gets no response from server
        """
        if self.state == CLOSED_STATE:
            print("[Initiating 3-way handshake]")
            self.tcp_header.set_syn(1)
            self.tcp_header.set_seq_num(random.randrange(2 ** 32 - 1))

            self.tcp_header.reset_checksum()
            message = self.tcp_header.get_binary_string()
            checksum = self.calculate_checksum(message.encode('utf-16'))
            self.tcp_header.set_checksum(checksum)
            self.client_socket.sendto(self.tcp_header.get_binary_string().encode('utf-16'), (self.udpl_ip_address, self.udpl_port))
            self.state = SYN_SENT_STATE
            print(f"[SYN handshake message sent to {(self.udpl_ip_address, self.udpl_port)}]")

            retry_thread = Thread(target=self.manage_handshake_timeout, args=(self.tcp_header.get_binary_string().encode('utf-16'),))
            retry_thread.start()

            while True:
                try:
                    if not self.listening_socket.fileno() == -1:
                        self.listening_socket.settimeout(2)
                        reply, address = self.listening_socket.recvfrom(2048)
                    else:
                        break
                except timeout:
                    if self.handshake_event.is_set():
                        break
                    else:
                        continue
                else:
                    self.handshake_event.set()
                    reply_string = reply.decode('utf-16')
                    reply_header = reply_string[:160]
                    server_seq_num = reply_header[32:64]
                    reply_ack_num = reply_header[64:96]

                    if int(reply_header[110]) == 1:
                        print("[SYNACK handshake message received]")
                        self.tcp_header.set_syn(0)
                        self.tcp_header.set_seq_num(int(reply_ack_num, 2))
                        self.tcp_header.set_ack_num(int(server_seq_num, 2) + 1)

                        self.tcp_header.reset_checksum()
                        message = self.tcp_header.get_binary_string()
                        checksum = self.calculate_checksum(message.encode('utf-16'))
                        self.tcp_header.set_checksum(checksum)
                        self.client_socket.sendto(self.tcp_header.get_binary_string().encode('utf-16'), (self.udpl_ip_address, self.udpl_port))
                        print(f"[ACK sent to {(self.udpl_ip_address, self.udpl_port)}, connection established]")
                        self.tcp_header.reset_ack_flag()
                        self.state = ESTABLISHED_STATE
                        break
            retry_thread.join()

    def manage_handshake_timeout(self, message):
        """
        Tracks number of retries and performs retries until no. of retries is MAX_RETRIES
        :param message: Encoded message including payload (empty for handshake) and header
        :return:
        """
        retries = 0
        while retries < MAX_RETRIES and not self.handshake_event.is_set():
            time.sleep(10)
            if not self.handshake_event.is_set():
                self.tcp_header.reset_checksum()
                self.tcp_header.set_checksum(self.calculate_checksum(message))
                self.client_socket.sendto(self.tcp_header.get_binary_string().encode('utf-16'), (self.udpl_ip_address, int(self.udpl_port)))
                retries += 1
                print(f"Retrying handshake {retries} times")

        if not self.handshake_event.is_set():
            print("Max retries reached, closing the socket.")
            self.listening_socket.close()

    def transmit_data(self):
        """
        Transmits the data by reading from the given input file.
        Steps:
        1. Split data into chunks of size MSS (if size less than MSS, we get a single chunk)
        2. Add the packets to the buffer last packet first so that sequence number order is maintained while processing.
        3. Pipeline and send initial chunks in the window to the server at once. Increment next_seq_num by the length of
        each packet encountered
        4. Spin up threads to monitor the send window continuously, listen for ACKs and monitor the send base to ensure
        it is not equal to the last sequence number signalling end of transmission.
        """
        # Client can send and receive payload only if it is in ESTABLISHED state
        if self.state == ESTABLISHED_STATE:
            print("[Starting data transmission]")
            with open(self.input_file, 'rb') as file:
                data = file.read().decode('utf-16')
                file.close()
            # We reverse the list of packets so that we can pop the first packet first from the buffer
            splits = self.split_into_mss(data)
            self.last_seq_num = splits[-1][1]
            for tup in splits[::-1]:
                data_chunk = tup[0]
                seq_num = tup[1]
                self.ack_tracker[seq_num] = 0
                self.buffer.append(data_chunk)
                self.seq_num_to_chunk[seq_num] = data_chunk
                self.seq_num_to_is_retransmitted[seq_num] = False

            print(f"[Split the data into {len(self.buffer)} chunks]")

            listen_for_acks_thread = Thread(target=self.listen_for_acks, args=(), daemon=True)
            listen_for_acks_thread.start()
            # Pipeline and send initially
            while len(self.buffer) > 0 and self.next_seq_num < self.send_base + self.windowsize:
                self.tcp_header.set_seq_num(self.next_seq_num)
                packet = self.buffer.pop()
                self.tcp_header.reset_checksum()
                message = self.tcp_header.get_binary_string().encode('utf-16') + packet
                self.tcp_header.set_checksum(self.calculate_checksum(message))
                message = self.tcp_header.get_binary_string().encode('utf-16') + packet
                self.client_socket.sendto(message, (self.udpl_ip_address, self.udpl_port))
                print(f"[Sent initial packets of sequence number {self.next_seq_num}]")
                if self.seq_num_to_is_retransmitted.get(self.next_seq_num) is not None and not self.seq_num_to_is_retransmitted[self.next_seq_num]:
                    self.seq_num_to_transmit_time[self.next_seq_num] = time.time()
                    # We increment by length of packet and not MSS to account for packets of length < MSS
                    self.next_seq_num += len(packet)

            monitor_send_window_thread = Thread(target=self.monitor_send_window, args=(), daemon=True)
            monitor_send_window_thread.start()
            monitor_send_base_thread = Thread(target=self.monitor_send_base, args=(), daemon=True)
            monitor_send_base_thread.start()
            monitor_send_base_thread.join()
            listen_for_acks_thread.join(timeout=2)
            return

    def monitor_send_base(self):
        """
        Monitors the send base to ensure it is not equal to the last sequence number signalling end of transition.
        """
        while True:
            if self.send_base == self.last_seq_num:
                print("[End of transmission]")
                self.end_transmission = True
                break

    def monitor_send_window(self):
        """
        Monitors the next sequence number and the send base to ensure that the send window is maintained i.e.
        number of sent but unacknowledged packets do not cross the window size. Keep sending packets while this
        condition is satisfied
        :return:
        """
        while True:
            # Send as long as there are packets in the window to be sent and buffer is non-empty
            if len(self.buffer) == 0:
                break
            while self.next_seq_num < self.send_base + self.windowsize:
                if len(self.buffer) == 0:
                    break
                self.tcp_header.set_seq_num(self.next_seq_num)
                packet = self.buffer.pop()
                self.tcp_header.reset_checksum()
                message = self.tcp_header.get_binary_string().encode('utf-16') + packet
                self.tcp_header.set_checksum(self.calculate_checksum(message))
                message = self.tcp_header.get_binary_string().encode('utf-16') + packet
                self.client_socket.sendto(message, (self.udpl_ip_address, self.udpl_port))
                print(f"[Sent packet of sequence number {self.next_seq_num}]")
                if not self.seq_num_to_is_retransmitted[self.next_seq_num]:
                    self.seq_num_to_transmit_time[self.next_seq_num] = time.time()
                self.next_seq_num += len(packet)  # Increment next_seq_num by length of data whenever we send a packet

    def listen_for_acks(self):
        """
        * Listens for ACKs to sequence numbers transmitted and performs Go-Back-N on timeout.
        * Performs fast retransmit if 3 duplicate ACKs are received.
        * Every time an ACK is successfully received, the send base moves forward and SampleRTT is recalculated based on
        time at which the packet was originally sent, provided the packet has not been retransmitted
        * When a timeout occurs, the interval is doubled and Go-Back-N is executed
        """
        self.listening_socket.settimeout(min(self.timeout_interval, 5))
        while True:
            try:
                reply, address = self.listening_socket.recvfrom(2048)

                reply_header = reply.decode('utf-16')[:160]
                # If the 107th bit corresponding to ACK flag is set, it is an ACK message
                if int(reply_header[107]) == 1 and self.state == ESTABLISHED_STATE:
                    reply_ack_num = reply_header[64:96]
                    ack_seq_num_bin = reply_header[32:64]
                    ack_seq_num_int = int(ack_seq_num_bin, 2)  # sequence number for which it is the ACK
                    print(f"[ACK received for sequence number {ack_seq_num_int}]")
                    # Move send_base whenever a packet gets acknowledged
                    self.send_base += len(self.seq_num_to_chunk)
                    if self.seq_num_to_is_retransmitted.get(ack_seq_num_int) is not None and not self.seq_num_to_is_retransmitted[ack_seq_num_int]:
                        self.sample_rtt = time.time() - self.seq_num_to_transmit_time[ack_seq_num_int]
                        self.timeout_interval = self.get_timeout()
                        print(f"[Timeout interval recalculated and set to {self.timeout_interval}]")
                        self.ack_tracker[ack_seq_num_int] += 1

                    # If 3 ACKS for the same sequence number have been received, we perform fast retransmit
                    if self.ack_tracker.get(ack_seq_num_int) is not None and self.ack_tracker[ack_seq_num_int] >= 3:
                        print(f"[Performing fast retransmit for sequence number {ack_seq_num_int}]")
                        self.seq_num_to_is_retransmitted[ack_seq_num_int] = True  # setting the is_transmitted flag to True
                        packet = self.seq_num_to_chunk[ack_seq_num_int]
                        self.tcp_header.reset_checksum()
                        message = self.tcp_header.get_binary_string().encode('utf-16') + packet
                        self.tcp_header.set_checksum(self.calculate_checksum(message))
                        message = self.tcp_header.get_binary_string().encode('utf-16') + packet
                        self.client_socket.sendto(message, (self.udpl_ip_address, self.udpl_port))
                        self.ack_tracker[ack_seq_num_int] = 0
            except timeout:
                self.timeout_interval = self.timeout_interval * 2
                if self.timeout_interval > MAX_TIMEOUT:
                    print("[Max timeout reached, exiting]")
                    self.client_socket.close()
                    self.listening_socket.close()
                    sys.exit()
                print(f"[Timer expired, doubling timeout interval to {self.timeout_interval}]")
                curr_seq_num = self.send_base
                while curr_seq_num < self.next_seq_num and not self.end_transmission:
                    if self.seq_num_to_chunk.get(curr_seq_num) is not None:
                        self.seq_num_to_is_retransmitted[curr_seq_num] = True
                        packet = self.seq_num_to_chunk[curr_seq_num]
                        self.tcp_header.reset_checksum()
                        message = self.tcp_header.get_binary_string().encode('utf-16') + packet
                        self.tcp_header.set_checksum(self.calculate_checksum(message))
                        message = self.tcp_header.get_binary_string().encode('utf-16') + packet
                        self.client_socket.sendto(message, (self.udpl_ip_address, self.udpl_port))
                        print(f"[Go-Back-N: Sent packet of sequence number {curr_seq_num}]")
                        curr_seq_num += len(packet)

    def split_into_mss(self, data):
        """
        Splits input data into partitions of size MSS.
        :param data: String data/payload
        :return: List of tuples (data chunk, sequence number)
        """
        res = []
        curr_seq_num = 0
        data_bits = data.encode('utf-16')
        stride = MSS
        for i in range(0, len(data_bits), stride):
            if i == 0:
                res.append((data_bits[i:i + stride], self.tcp_header.seq_num[0]))
                curr_seq_num = self.tcp_header.seq_num[0]
                # initializing next_seq_num and send_base as the first sequence number
                self.next_seq_num = curr_seq_num
                self.send_base = curr_seq_num
            else:
                res.append((data_bits[i:i + stride], curr_seq_num + MSS))
        return res

    def get_estimated_rtt(self):
        self.estimated_rtt = (1 - ALPHA) * self.estimated_rtt + ALPHA * self.sample_rtt
        return self.estimated_rtt

    def get_dev_rtt(self):
        self.dev_rtt = (1 - BETA) * self.dev_rtt + BETA * abs(self.sample_rtt - self.estimated_rtt)
        return self.dev_rtt

    def get_timeout(self):
        return self.get_estimated_rtt() + 4 * self.get_dev_rtt()

    def close_connection(self):
        """
        Performs connection teardown using FIN handshake mechanism
        """
        print("[Initiating connection close]")
        self.tcp_header.set_fin(1)
        # Sending only the TCP header without any application layer data since it is a handshake message
        self.tcp_header.reset_checksum()
        message = self.tcp_header.get_binary_string().encode('utf-16')
        self.tcp_header.set_checksum(self.calculate_checksum(message))
        self.client_socket.sendto(self.tcp_header.get_binary_string().encode('utf-16'), (self.udpl_ip_address, self.udpl_port))
        print("[Sent FIN handshake message]")
        self.state = FIN_WAIT_1_STATE

        listen_for_fin_acks_thread = Thread(target=self.listen_for_fin_acks, args=(self.tcp_header.get_binary_string().encode('utf-16'),), daemon=True)
        listen_for_fin_acks_thread.start()
        listen_for_fin_acks_thread.join()
        return

    def listen_for_fin_acks(self, message):
        """
        List for the ACKs from the server during connection teardown process
        :param message: Message to be resent during retries
        """
        retry_thread = Thread(target=self.manage_handshake_timeout, args=(message,))
        retry_thread.start()

        while True:
            try:
                if not self.listening_socket.fileno() == -1:
                    self.listening_socket.settimeout(5)
                    reply, address = self.listening_socket.recvfrom(2048)
                else:
                    break
            except timeout:
                if self.handshake_event.is_set():
                    break
                else:
                    continue
            else:
                self.handshake_event.set()
                reply_string = reply.decode('utf-16')
                reply_header = reply_string[:160]  # The fixed TCP header has 20 bytes i.e. 160 bits

                if int(reply_header[111]) == 0 and self.state == FIN_WAIT_1_STATE:
                    print("[Received FINACK handshake message]")
                    self.handshake_event.set()
                    retry_thread.join(timeout=1)
                    self.state = FIN_WAIT_2_STATE
                    message = self.tcp_header.get_binary_string()
                    retry_thread = Thread(target=self.manage_handshake_timeout, args=(message,))
                    retry_thread.start()

                elif int(reply_header[111]) == 1 and self.state == FIN_WAIT_2_STATE:
                    print("[Received final ACK from server]")
                    self.handshake_event.set()
                    retry_thread.join(timeout=1)
                    self.tcp_header.set_fin(0)
                    self.tcp_header.reset_checksum()
                    message = self.tcp_header.get_binary_string()
                    self.tcp_header.set_checksum(self.calculate_checksum(message.encode('utf-16')))
                    self.client_socket.sendto(self.tcp_header.get_binary_string().encode('utf-16'), (self.udpl_ip_address, self.udpl_port))
                    print("[Sent FIN handshake message]")
                    self.state = TIME_WAIT_STATE
                    time.sleep(2)
                    self.state = CLOSED_STATE
                    print("[Connection closed]")
                    retry_thread.join()
                    self.client_socket.close()
                    self.listening_socket.close()
                    break
        retry_thread.join()

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
        print("[Checksum computed:" + str(checksum) + "]")
        return checksum

if __name__ == '__main__':
    try:
        input_file = sys.argv[1]
        ip_address_of_udpl = sys.argv[2]
        port_number_of_udpl = sys.argv[3]
        windowsize = sys.argv[4]
        ack_port_number = sys.argv[5]
        if int(port_number_of_udpl) < 1024 or int(port_number_of_udpl) > 65535:
            raise ValueError("[UDPL port number specified is invalid]")

        if int(ack_port_number) < 1024 or int(ack_port_number) > 65535:
            raise ValueError("[ACK port number specified is invalid]")

        if re.search("^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$", ip_address_of_udpl) is None:
            sys.exit("[Invalid UDPL IP address specified]")

        client = Client(ack_port_number, port_number_of_udpl, input_file, ip_address_of_udpl, windowsize)
        client.three_way_handshake()
        client.transmit_data()
        client.close_connection()

    except Exception as e:
        print(f"[Invalid arguments]: {e}")
        traceback.print_exc()
        sys.exit("[Exiting]")

