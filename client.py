from crypto import Crypto, NexonCRC16
from packet import ServerPacket, ClientPacket
from server import ServerInfo, LoginServer

import random
import socket
import struct
import threading
from time import time, sleep
from numpy import uint8, uint16, uint32, int32


class Client(object):
    da_version = 739
    start_time = 0
    client_ordinal = 0
    socket = None
    server = None
    sent_version = False
    crypto = None
    username = None
    password = None
    show_outgoing = False
    show_incoming = False
    recv_buffer = []
    packet_handlers = {}

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.crypto = Crypto()
        self.start_time = time()
        self.recv_buffer = []

        self.packet_handlers[0x00] = self.packet_handler_0x00_encryption
        self.packet_handlers[0x02] = self.packet_handler_0x02_login_message
        self.packet_handlers[0x03] = self.packet_handler_0x03_redirect
        self.packet_handlers[0x05] = self.packet_handler_0x05_user_id
        self.packet_handlers[0x0A] = self.packet_handler_0x0A_system_message
        self.packet_handlers[0x0D] = self.packet_handler_0x0D_chat
        self.packet_handlers[0x3B] = self.packet_handler_0x3B_ping_a
        self.packet_handlers[0x4C] = self.packet_handler_0x4C_ending_signal
        self.packet_handlers[0x68] = self.packet_handler_0x68_ping_b
        self.packet_handlers[0x7E] = self.packet_handler_0x7E_welcome

    @classmethod
    def run(cls, username, password):
        client = cls(username, password)
        client.connect()

        while True:
            try:
                if client.recv_buffer:
                    client.handle_recv(client.recv_buffer.pop(0))
                sleep(0.10)
            except KeyboardInterrupt:
                break

        client.disconnect()

    @property
    def tick_count(self):
        return time() - self.start_time

    def connect(self, address=None, port=None):
        if not address:
            address = LoginServer.address
            port = LoginServer.port

        server = ServerInfo.from_ip_address(address, port)

        print("Connecting to {0}...".format(server.name))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if server == LoginServer:
            self.socket.settimeout(5)
        self.socket.connect((address, port))

        print("Connected.")
        self.server = server

        socket_thread = threading.Thread(target=ioloop, args=(self,))
        socket_thread.start()

    def disconnect(self):
        if self.server:
            print("Disconnected from {0}.".format(self.server.name))
            self.server = None
        if self.socket:
            self.socket.close()
            self.socket = None

    def reconnect(self):
        self.disconnect()
        self.client_ordinal = 0
        self.sent_version = False
        self.connect()

    def send(self, packet):
        if packet.should_encrypt:
            packet.ordinal = self.client_ordinal
            self.client_ordinal = uint8(self.client_ordinal + 1)
            packet.encrypt(self.crypto)

        # Wait for new socket to connect
        while not self.socket:
            sleep(0.10)

        self.socket.send(packet.to_bytearray())

        if self.show_outgoing:
            print("Sent: {0}".format(packet.to_string()))

    def connected_to_login(self):
        self.login()

    def connected_to_world(self):
        print("Logged into {0} as {1}.".format(self.server.name, self.username))
        self.send(ClientPacket(0x2D))

    def _login(self):
        # TODO: Figure out why this client_id isn't working

        print("Logging in as {0}... ".format(self.username))
        x03 = ClientPacket(0x03)
        x03.write_string8(self.username)
        x03.write_string8(self.password)

        key_1 = random.randint(0, 0xFF)
        key_2 = random.randint(0, 0xFF)

        client_id_1 = random.randint(0, 0xFFFFFFFF)
        client_id_1_key = uint8(key_2 + 138)
        client_id_1 ^= uint32(client_id_1_key | ((client_id_1_key + 1) << 8) | ((client_id_1_key + 2) << 16) | ((client_id_1_key + 3) << 24))

        crc = NexonCRC16.crc_16_table
        packed = struct.pack('I', client_id_1)
        unpacked = list(struct.unpack('BBBB', packed))

        v1 = unpacked[1] ^ uint16(((uint8(client_id_1) ^ crc[0]) << 8) ^ crc[(int32(uint16((uint8(client_id_1) ^ crc[0]))) >> 8) & 0xFF])
        v2 = uint8(client_id_1 >> 16) ^ uint16((v1 << 8) ^ crc[(int32(v1) >> 8) & 0xFF])
        client_id_2 = uint16(unpacked[3] ^ (v2 << 8) ^ uint16(crc[(int32(v2) >> 8) & 0xFF]))

        random_val = random.randint(0, 0xFFFF)
        random_val_key = uint8(key_2 + 115)
        random_val ^= uint32(random_val_key | ((random_val_key + 1) << 8) | ((random_val_key + 2) << 16) | ((random_val_key + 3) << 24))

        x03.write_byte(key_1)
        x03.write_byte(uint8(key_2 ^ (key_1 + 59)))
        x03.write_uint32(client_id_1)
        x03.write_uint16(client_id_2)
        x03.write_uint32(random_val)

        crc = NexonCRC16.calculate(x03.data, len(self.username) + len(self.password) + 2, 12)
        crc_key = uint8(key_2 + 165)
        crc ^= uint16(crc_key | (crc_key + 1) << 8)

        x03.write_uint16(crc)
        x03.write_uint16(0x0100)

        self.send(x03)

    def login(self):
        """
        Log in using a client_id taken from a real client.
        This is a temporary workaround until I figure out
        how to properly generate one.
        """

        print("Logging in as {0}... ".format(self.username))
        x03 = ClientPacket(0x03)
        x03.write_string8(self.username)
        x03.write_string8(self.password)
        x03.write_byte(0xE0)
        x03.write_byte(0xC0)
        x03.write_uint32(0x8A39DBB2)
        x03.write_uint16(0x9E1D)
        x03.write_uint32(0x263D94DF)
        x03.write_uint16(0x6749)
        x03.write_uint16(0x0100)
        self.send(x03)

    def packet_handler_0x00_encryption(self, packet):
        code = packet.read_byte()
        if code == 1:
            self.da_version -= 1
            print("Invalid DA version, possibly too high. "
                  "Trying again with {0}.".format(self.da_version))
            self.reconnect()
            return
        elif code == 2:
            version = packet.read_int16()
            packet.read_byte()
            packet.read_string8()  # patch url
            self.da_version = version
            print("Your DA version is too low. "
                  "Setting DA version to {0}.".format(version))
            self.reconnect()
            return

        packet.read_uint32()  # server table crc
        seed = packet.read_byte()
        key = packet.read_string8()

        self.crypto = Crypto(seed, key)

        x57 = ClientPacket(0x57)
        x57.write_uint32(0)
        self.send(x57)

    def packet_handler_0x02_login_message(self, packet):
        """
        Code 0: Success
        Code 3: Invalid name or password
        Code 14: Name does not exist
        Code 15: Incorrect password
        """
        code = packet.read_byte()
        message = packet.read_string8()

        if code == 0:
            print("Login success!")
        elif code == 3 or code == 14 or code == 15:
            print(message)
        else:
            print(message)
            self.login()

    def packet_handler_0x03_redirect(self, packet):
        address = packet.read(4)
        port = packet.read_uint16()
        packet.read_byte()  # remaining
        seed = packet.read_byte()
        key = packet.read_string8()
        name = packet.read_string8()
        id = packet.read_uint32()

        self.crypto = Crypto(seed, key, name)

        address.reverse()
        address = ".".join([str(octet) for octet in address])

        self.disconnect()
        self.connect(address, port)

        x10 = ClientPacket(0x10)
        x10.write_byte(seed)
        x10.write_string8(key)
        x10.write_string8(name)
        x10.write_uint32(id)
        x10.write_byte(0x00)
        self.send(x10)

        if self.server == LoginServer:
            self.connected_to_login()

    def packet_handler_0x05_user_id(self, packet):
        self.connected_to_world()

    def packet_handler_0x0A_system_message(self, packet):
        pass

    def packet_handler_0x0D_chat(self, packet):
        pass

    def packet_handler_0x3B_ping_a(self, packet):
        hi_byte = packet.read_byte()
        lo_byte = packet.read_byte()

        x45 = ClientPacket(0x45)
        x45.write_byte(lo_byte)
        x45.write_byte(hi_byte)
        self.send(x45)

    def packet_handler_0x4C_ending_signal(self, packet):
        x0B = ClientPacket(0x0B)
        x0B.write_boolean(False)
        self.send(x0B)

    def packet_handler_0x68_ping_b(self, packet):
        timestamp = packet.read_int32()

        x75 = ClientPacket(0x75)
        x75.write_int32(timestamp)
        x75.write_int32(int(self.tick_count))
        self.send(x75)

    def packet_handler_0x7E_welcome(self, packet):
        if self.sent_version:
            return

        x62 = ClientPacket(0x62)
        x62.write_byte(0x34)
        x62.write_byte(0x00)
        x62.write_byte(0x0A)
        x62.write_byte(0x88)
        x62.write_byte(0x6E)
        x62.write_byte(0x59)
        x62.write_byte(0x59)
        x62.write_byte(0x75)
        self.send(x62)

        x00 = ClientPacket(0x00)
        x00.write_int16(self.da_version)
        x00.write_byte(0x4C)
        x00.write_byte(0x4B)
        x00.write_byte(0x00)
        self.send(x00)

        self.sent_version = True

    def handle_recv(self, recv_buffer):
        recv_buffer = struct.unpack('B' * len(recv_buffer), recv_buffer)

        if not recv_buffer:
            self.disconnect()
            return

        while len(recv_buffer) > 3:
            if recv_buffer[0] != 0xAA:
                return

            length = recv_buffer[1] << 8 | recv_buffer[2] + 3

            if length > len(recv_buffer):
                break

            buffer = list(recv_buffer[:length])
            recv_buffer = recv_buffer[length:]

            packet = ServerPacket(buffer)

            if packet.should_encrypt:
                packet.decrypt(self.crypto)

            if self.show_incoming:
                print("Received: {0}".format(packet.to_string()))

            if packet.opcode in self.packet_handlers:
                self.packet_handlers[packet.opcode](packet)


def ioloop(client):
    s = client.socket
    while True:
        try:
            recv_buffer = s.recv(4096)
            client.recv_buffer.append(recv_buffer)
        except socket.timeout:
            break
        except socket.error:
            break

        if not recv_buffer:
            break
    s.close()
