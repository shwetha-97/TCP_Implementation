
class TCPHeader(object):

    def __init__(self, source_port, dest_port):
        # each field is represented as (int value, number of bits)
        # CWR and ECE fields are not mentioned because we are following conventional TCP header format
        self.source_port = (int(source_port), 16)  # 0-15
        self.dest_port = (int(dest_port), 16)  # 16-31
        self.seq_num = (0, 32)  # 32-63
        self.ack_num = (0, 32)  # 64-95
        self.header_length = (5, 4)  # 96-99
        self.unused = (0, 6)  # 100-105
        self.urg = (0, 1)  # unused here, setting to default value, 106
        self.ack = (0, 1)  # 107
        self.psh = (0, 1)  # unused here, setting to default value, 108
        self.rst = (0, 1)  # unused here, setting to default value, 109
        self.syn = (0, 1)  # 110
        self.fin = (0, 1)  # 111
        self.receive_window = (8192, 16)  # unused in this implementation, setting to default value, 112-127
        self.checksum = (0, 16)  # 128-143
        self.urgent_data_pointer = (0, 16)  # 144-159

    def set_seq_num(self, seq_num):
        self.seq_num = (self.check_length_and_get_val(seq_num, 32, "Sequence Number"), 32)

    def set_ack_num(self, ack_num):
        try:
            self.ack_num = (self.check_length_and_get_val(ack_num, 32, "ACK number"), 32)
            self.ack = (1, 1)
        except ValueError as e:
            self.ack = (0, 1)

    def reset_ack_flag(self):
        self.ack = (0, 1)

    def set_checksum(self, checksum):
        self.checksum = (self.check_length_and_get_val(checksum, 16, "Checksum"), 16)

    def reset_checksum(self):
        self.checksum = (0, 16)

    def set_syn(self, syn):
        self.syn = (self.check_length_and_get_val(syn, 1, "SYN"), 1)

    def set_fin(self, fin):
        self.fin = (self.check_length_and_get_val(fin, 1, "FIN"), 1)

    def get_binary_string(self):
        """
        Join all the fields of the TCP header based on the number of bits given so that we get a binary string of length 160
        :return: Binary string of length 160
        """
        b = ''
        for item in self.__dict__.values():
            int_val, num_bits = item
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
        """
        Checks if the field adheres to size amd value constraints
        :param int_val: Integer value of the field
        :param max_len: Max length of the field value in bits
        :param name: Name of the field for logging
        :return:
        """
        error_string = name + " too long"
        if int_val.bit_length() > max_len:
            raise ValueError(error_string)
        return int_val

