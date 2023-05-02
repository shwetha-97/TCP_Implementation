import sys
import time
import traceback
from tcpheader import TCPHeader
from socket import *

MSS = 576
ALPHA = 0.125
BETA = 0.25

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
        self.state = CLOSED_STATE  # make sure this is part of an enum of states allowed for server
        self.input_file = input_file
        self.source_port = source_port  # port where we get ACKs
        self.client_socket = socket(AF_INET, SOCK_DGRAM)
        self.client_socket.bind(('', int(self.source_port)))
        self.udpl_port = udpl_port
        self.udpl_ip_address = udpl_ip_address
        self.windowsize = windowsize
        self.windowsize_N = self.windowsize/MSS
        self.window = []
        self.timeout_interval = 3
        self.sample_rtt = 0
        self.estimated_rtt = 0
        self.dev_rtt = 0
        self.ack_tracker = {}  # stores sequence_number: no.of acks received
        self.seq_num_to_chunk = {}  # stores sequence_number: TCP segment.
        # We store is_retransmitted so that we identify and don't update timeout for retransmitted packets
        # We store is_completed so that if ACKs for all packets are completed, we return a success and stop listening
        self.seq_num_to_is_retransmitted = {}  # stores sequence_number: is_retransmitted
        self.seq_num_to_transmit_time = {}  # storing the time each packet was transmitted for the first time, used to calculate sample RTT
        self.send_base = 0  # start of window, last sequence number that was sent but not ACKed
        self.next_seq_num = 0  # the next sequence number which needs to be resent
        self.last_seq_num = 0
        
    def three_way_handshake(self):
        if self.state == CLOSED_STATE:
            self.tcp_header.set_syn(1)
            self.tcp_header.set_seq_number(random.randrange(2**32 - 1))
            # Sending only the TCP header without any application layer data since it is a handshake message
            message = self.tcp_header.get_binary_string().encode()

            self.client_socket.sendto(message, (self.udpl_ip_address, int(self.udpl_port)))
            self.state = SYN_SENT_STATE

            reply, address = self.client_socket.recvfrom(2048)
            reply_string = reply.decode()
            reply_header = reply_string[:161]  # The fixed TCP header has 20 bytes i.e. 160 bits
            # bits 32 to 63 inclusive in the header are the bits corresponding to the sequence number
            server_seq_num = reply_header[32:64]
            # bits 64 to 95 inclusive in the header are the bits corresponding to the ACK number
            reply_ack_num = reply_header[64:96]
            # 110th bit in the TCP header is the SYN bit
            if reply_header[110] == 1:
                self.tcp_header.set_syn(0)
                self.tcp_header.set_seq_num(int(reply_ack_num))  # ACK number of response is the client's
                # initial seq num + 1, which is set as the next sequence number
                self.tcp_header.set_ack_num(int(server_seq_num) + 1)  # The ACK is set as the sequence number + 1
                tcp_header_bin_string = self.tcp_header.get_binary_string()
                # Sending only the TCP header without any application layer data since it is a handshake message
                message = tcp_header_bin_string.encode()

                self.client_socket.sendto(message, (self.udpl_ip_address, int(self.udpl_port)))
                self.tcp_header.reset_ack_flag()
                self.state = ESTABLISHED_STATE

    def transmit_data(self):
        # Client can send and receive payload only if it is in ESTABLISHED state
        if self.state == ESTABLISHED_STATE:
            with open(self.input_file, 'r') as file:
                data = file.read()
            # We reverse the list of packets so that we can pop the first packet first from the buffer
            for tup in self.split_into_mss(data)[::-1]:
                data_chunk = tup[0]
                seq_num = tup[1]
                self.ack_tracker[seq_num] = 0
                self.buffer.append(data_chunk)
                self.seq_num_to_chunk[seq_num] = data_chunk
                self.seq_num_to_is_retransmitted[seq_num] = False

            listen_for_acks_thread = Thread(target=self.listen_for_acks, args=(), daemon=True)
            manage_timeout_thread = Thread(target=self.manage_timeout, args=(), daemon=True)
            # send the first N packets in the buffer
            for i in range(self.windowsize_N):
                self.tcp_header.set_seq_num(self.next_seq_num)
                packet = buffer.pop()
                message = self.tcp_header.get_binary_string().encode() + packet.encode()
                self.client_socket.sendto(message, (self.udpl_ip_address, int(self.udpl_port)))
                if not self.seq_num_to_is_retransmitted[self.next_seq_num]:
                    self.seq_num_to_transmit_time[self.next_seq_num] = time.time()
                # We increment by length of packet and not MSS to account for packets of length < MSS
                self.next_seq_num += len(packet.encode())

            monitor_send_window_thread = Thread(target=self.monitor_send_window, args=())
            monitor_send_window_thread.join()
            monitor_send_base_thread = Thread(target=self.monitor_send_base, args=())
            monitor_send_base_thread.join()
            listen_for_acks_thread.join()
            manage_timeout_thread.join()
            return

    def monitor_send_base(self):
        while True:
            if self.send_base == self.last_seq_num:
                return

    def monitor_send_window(self):
        while True:
            # Send as long as there are packets in the window to be sent and buffer is non-empty
            if len(buffer) == 0:
                return
            while self.next_seq_num < self.send_base + self.windowsize_N:
                if len(buffer) == 0:
                    return
                self.tcp_header.set_seq_num(self.next_seq_num)
                packet = buffer.pop()
                message = self.tcp_header.get_binary_string().encode() + packet.encode()
                self.client_socket.sendto(message, (self.udpl_ip_address, int(self.udpl_port)))
                if not self.seq_num_to_is_retransmitted[self.next_seq_num]:
                    self.seq_num_to_transmit_time[self.next_seq_num] = time.time()
                self.next_seq_num += len(packet.encode())  # Increment next_seq_num by length of data whenever we send a packet


    def manage_timeout_and_gobackn(self):
        while True:
            start_time = time.time()
            self.start_timeout(start_time)
            # go-back-n retransmit from the send_base to the nextseqnum (not inclusive)
            # after the timer expires
            curr_seq_num = self.send_base
            while curr_seq_num < self.next_seq_num:
                self.client_socket.sendto(self.seq_num_to_chunk[curr_seq_num], (self.udpl_ip_address, int(self.udpl_port)))

    def start_timeout(self, start_time):
        while True:
            if time.time() - start_time >= self.timeout_interval:
                return

    def listen_for_acks(self):
        while True:
            reply, address = self.client_socket.recvfrom(2048)
            reply_header = reply.decode()[:161]
            # If the 37th bit corresponding to ACK flag is set, it is an ACK message
            if reply_header[37].decode() == 1:
                reply_ack_num = reply_header[64:96]
                ack_seq_num_bin = reply_header[32:64]
                ack_seq_num_int = int(ack_seq_num_bin, 2)  # sequence number for which it is the ACK
                # Move send_base whenever a packet gets acknowledged
                self.send_base += len(self.seq_num_to_chunk.encode())
                if not self.seq_num_to_is_retransmitted[ack_seq_num_int]:
                    self.sample_rtt = time.time() - self.seq_num_to_transmit_time[ack_seq_num_int]
                self.ack_tracker[ack_seq_num_int] += 1

                # If 3 ACKS for the same sequence number have been received, we perform fast retransmit
                if self.ack_tracker[ack_seq_num_int] >= 3:
                    self.seq_num_to_is_retransmitted[ack_seq_num_int] = True  # setting the is_transmitted flag to True
                    self.client_socket.sendto(self.seq_num_to_chunk[ack_seq_num_int], (self.udpl_ip_address, int(self.udpl_port)))

    def split_into_mss(self, data):
        res = []
        curr_seq_num = 0
        data_bits = data.encode()
        stride = MSS * 8  # since MSS is specified in bytes, we convert it to bits since data is in bits
        for i in range(0, len(data_bits), stride):
            if i == 0:
                res.append((data_bits[i:i + stride], self.tcp_header.self.seq_num[0]))
                curr_seq_num = self.tcp_header.self.seq_num[0]
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
        self.tcp_header.set_fin(1)
        # Sending only the TCP header without any application layer data since it is a handshake message
        message = self.tcp_header.get_binary_string().encode()

        self.client_socket.sendto(message, (self.udpl_ip_address, int(self.udpl_port)))
        self.state = FIN_WAIT_1_STATE

        listen_for_fin_acks_thread = Thread(target=self.listen_for_acks, args=())
        listen_for_fin_acks_thread.join()

    def listen_for_fin_acks(self):
        while True:
            reply, address = self.client_socket.recvfrom(2048)
            reply_string = reply.decode()
            reply_header = reply_string[:161]  # The fixed TCP header has 20 bytes i.e. 160 bits
            if reply_header[96] == 0 and self.state == FIN_WAIT_1_STATE:
                self.state = FIN_WAIT_2_STATE  # FINACK received
            elif reply_header[96] == 1 and self.state == FIN_WAIT_2_STATE:
                self.state = TIME_WAIT_STATE
                time.sleep(30)
                self.state = CLOSED_STATE
                return


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
        print(f">>> [Invalid arguments]: {e}")
        traceback.print_exc()
        sys.exit(">>> [Exiting]")

