
class TCPHeader(object):

    def __init__(self, source_port, dest_port, windowsize):
        # checks each of the fields to ensure they adhere to size amd value constraints
        # each field is represented as (int value, number of bits)
        # CWR and ECE fields are not mentioned because we are following conventional TCP header format
        self.source_port = (source_port, 16)
        self.dest_port = (dest_port, 16)
        self.seq_num = (0, 32)
        self.ack_num = (0, 32)
        self.header_length = (5, 4)
        self.unused = (0, 6)
        self.urg = (0, 1)  # unused, set to default value
        self.ack = (0, 1)
        self.psh = (0, 1)  # unused, set to default value
        self.rst = (0, 1)  # unused, set to default value
        self.syn = (0, 1)
        self.fin = (0, 1)
        self.receive_window = (windowsize, 16)  # default value is (8192, 16)
        self.checksum = (0, 16)
        self.urgent_data_pointer = (0, 16)
        self.options = (0, 0)  # unused, set to default value

    def set_seq_num(self, seq_num):
        self.seq_num = (self.check_length_and_get_val(seq_num, 32, "Sequence Number"), 4)

    def set_ack_num(self, ack_num):
        try:
            self.ack_num = (self.check_length_and_get_val(ack_num, 32, "ACK number"), 4)
        except ValueError as e:
            self.ack = 1

    def reset_ack_flag(self):
        self.ack = (0, 1)

    def set_syn(self, syn):
        self.syn = (self.check_length_and_get_val(syn, 1, "SYN"), 1)

    def set_fin(self, fin):
        self.fin = (self.check_length_and_get_val(fin, 1, "FIN"), 1)

    def get_binary_string(self):
        b = ''
        for int_val, num_bits in self.__dict__.values():
            # we need to pad the integer value with the number of bits
            b += format(int_val, 'b').zfill(num_bits)
        # returns a binary string (type = str)
        return b

    def get_header_length(self):
        length = 0
        for field_value in self.__dict__.values():
            length += len(field_value)

        if length > 20:
            raise AssertionError("Header greater than 20 bytes")
        return length

    def check_length_and_get_val(self, int_val, max_len, name):
        error_string = name + " too long"
        if int_val.bit_length() > max_len:
            raise ValueError(error_string)
        return int_val

    def calculate_checksum(self):
        pass

