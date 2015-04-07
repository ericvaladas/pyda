import struct
import random

from numpy import uint8, uint16, int32


class Packet(object):
    @property
    def should_encrypt(self):
        return self.encrypt_method != EncryptMethod.NoEncrypt

    def to_array(self):
        extra_length = 5 if self.should_encrypt else 4
        buffer_length = len(self.data) + extra_length
        buffer = []
        buffer.append(0xAA)
        buffer.append((buffer_length - 3) / 256)
        buffer.append(buffer_length - 3)
        buffer.append(self.opcode)
        if self.should_encrypt:
            buffer.append(self.ordinal)
        buffer += self.data

        return buffer

    def to_bytearray(self):
        return bytearray(self.to_array())

    def to_string(self):
        array = self.to_array()
        for index, element in enumerate(array):
            array[index] = '{:02X}'.format(element)

        return "-".join(array)

    def seek(self, offset, origin):
        if origin == Packet.PacketSeekOrigin.Begin:
            self.position = 0
        elif origin == Packet.PacketSeekOrigin.End:
            self.position = len(self.data)

        self.position += offset
        if self.position < 0:
            self.position = 0

        if self.position > len(self.data):
            self.position = len(self.data)

        return self.position


class ClientPacket(Packet):
    dialog_crc_table = [
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
        0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
        0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
        0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
        0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
        0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
        0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
        0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
        0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
        0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
        0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
        0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
        0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
        0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
        0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
        0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
        0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
        0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
        0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
        0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
        0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
        0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
        0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
        0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
        0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
        0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
        0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0]

    def __init__(self, opcode):
        self.opcode = opcode
        self.ordinal = 0
        self.position = 0
        self.data = []

    @property
    def encrypt_method(self):
        no_encrypt = [0x00, 0x10, 0x48]
        normal_encrypt = [
            0x02, 0x03, 0x04, 0x0B, 0x26, 0x2D, 0x3A, 0x42,
            0x43, 0x4B, 0x57, 0x62, 0x68, 0x71, 0x73, 0x7B]

        if self.opcode in no_encrypt:
            return EncryptMethod.NoEncrypt
        elif self.opcode in normal_encrypt:
            return EncryptMethod.Normal
        else:
            return EncryptMethod.MD5Key

    def write(self, buffer):
        self.data += buffer

    def write_byte(self, value):
        self.data.append(value)

    def write_sbyte(self, value):
        self.data.append(value)

    def write_boolean(self, value):
        self.data.append(0x01 if value else 0x00)

    def write_int16(self, value):
        packed = struct.pack('h', value)
        unpacked = struct.unpack('BB', packed)
        self.data.append(unpacked[1])
        self.data.append(unpacked[0])

    def write_uint16(self, value):
        packed = struct.pack('H', value)
        unpacked = struct.unpack('BB', packed)
        self.data.append(unpacked[1])
        self.data.append(unpacked[0])

    def write_int32(self, value):
        packed = struct.pack('i', value)
        unpacked = struct.unpack('BBBB', packed)
        self.data.append(unpacked[3])
        self.data.append(unpacked[2])
        self.data.append(unpacked[1])
        self.data.append(unpacked[0])

    def write_uint32(self, value):
        packed = struct.pack('I', value)
        unpacked = struct.unpack('BBBB', packed)
        self.data.append(unpacked[3])
        self.data.append(unpacked[2])
        self.data.append(unpacked[1])
        self.data.append(unpacked[0])

    def write_string(self, value):
        buffer = bytearray(value.encode('949'))
        self.data += buffer
        self.position += len(buffer)

    def write_string8(self, value):
        buffer = bytearray(value.encode('949'))
        self.data.append(len(buffer))
        self.data += buffer
        self.position += len(buffer) + 1

    def write_string16(self, value):
        buffer = bytearray(value.encode('949'))
        packed = struct.pack('H', len(value))
        unpacked = struct.unpack('BB', packed)
        self.data.append(unpacked[1])
        self.data.append(unpacked[0])
        self.data += buffer
        self.position += len(buffer) + 2

    def encrypt(self, crypto):
        if self.opcode == 0x39 or self.opcode == 0x3A:
            self.encrypt_dialog()

        key = ''
        self.position = len(self.data)

        rand_16 = random.randrange(65277) + 256
        rand_8 = random.randrange(155) + 100

        if self.encrypt_method == EncryptMethod.Normal:
            self.write_byte(0)
            key = crypto.key
        elif self.encrypt_method == EncryptMethod.MD5Key:
            self.write_byte(0)
            self.write_byte(self.opcode)
            key = crypto.generate_key(rand_16, rand_8)
        else:
            return

        for i in range(0, len(self.data)):
            salt_index = (i / len(crypto.key)) % 256

            self.data[i] ^= uint8(crypto.salt[salt_index] ^ ord(key[i % len(key)]))

            if salt_index != self.ordinal:
                self.data[i] ^= crypto.salt[self.ordinal]

        self.write_byte(uint8(rand_16 % 256 ^ 0x70))
        self.write_byte(uint8(rand_8 ^ 0x23))
        self.write_byte(uint8((rand_16 >> 8) % 256 ^ 0x74))

    def generate_dialog_helper(self):
        crc = 0
        for i in range(0, len(self.data) - 6):
            crc = self.data[6 + i] ^ ((crc << 8) ^ self.dialog_crc_table[(crc >> 8)])

        self.data[0] = random.randint(0, 255)
        self.data[1] = random.randint(0, 255)
        self.data[2] = len(self.data - 4) / 256
        self.data[3] = len(self.data - 4) % 256
        self.data[4] = crc / 256
        self.data[5] = crc % 256

    def encrypt_dialog(self):
        self.data = self.data[:6] + self.data[:len(self.data) - 6] + self.data[6:]

        self.generate_dialog_helper()

        length = self.data[2] << 8 | self.data[3]
        x_prime = self.data[0] - 0x2D
        x = self.data[1] ^ x_prime
        y = x + 0x72
        z = x + 0x28
        self.data[2] ^= y
        self.data[3] ^= (y + 1) % 256
        for i in range(0, length):
            self.data[4 + i] ^= (z + i) % 256


class ServerPacket(Packet):
    def __init__(self, buffer):
        self.opcode = buffer[3]
        self.position = 0

        if self.should_encrypt:
            self.ordinal = buffer[4]
            self.data = buffer[5:]
        else:
            self.data = buffer[4:]

    @property
    def encrypt_method(self):
        no_encrypt = [0x00, 0x03, 0x40, 0x7E]
        normal_encrypt = [0x01, 0x02, 0x0A, 0x56, 0x60, 0x62, 0x66, 0x6F]

        if self.opcode in no_encrypt:
            return EncryptMethod.NoEncrypt
        elif self.opcode in normal_encrypt:
            return EncryptMethod.Normal
        else:
            return EncryptMethod.MD5Key

    def read(self, length):
        if self.position + length > len(self.data):
            return 0

        buffer = self.data[self.position:length]
        self.position += length

        return buffer

    def read_byte(self):
        if self.position + 1 > len(self.data):
            return 0

        value = self.data[self.position]
        self.position += 1
        return value

    def read_sbyte(self):
        if self.position + 1 > len(self.data):
            return 0

        value = self.data[self.position]
        self.position += 1
        return value

    def read_boolean(self):
        if self.position + 1 > len(self.data):
            return False

        value = self.data[self.position] != 0
        self.position += 1
        return value

    def read_int16(self):
        if self.position + 2 > len(self.data):
            return 0

        value = self.data[self.position] << 8 | self.data[self.position + 1]
        self.position += 2

        return value

    def read_uint16(self):
        if self.position + 2 > len(self.data):
            return 0

        value = self.data[self.position] << 8 | self.data[self.position + 1]
        self.position += 2

        return value

    def read_int32(self):
        if self.position + 4 > len(self.data):
            return 0

        value = self.data[self.position] << 24 | self.data[self.position + 1] << 16 | self.data[self.position + 2] << 8 | self.data[self.position + 3]
        self.position += 4

        return int32(value)

    def read_uint32(self):
        if self.position + 4 > len(self.data):
            return 0

        value = self.data[self.position] << 24 | self.data[self.position + 1] << 16 | self.data[self.position + 2] << 8 | self.data[self.position + 3]
        self.position += 4

        return value

    def read_string8(self):
        if self.position + 1 > len(self.data):
            return ""

        length = self.data[self.position]
        position = self.position + 1

        if position + length > len(self.data):
            return ""

        buffer = self.data[position:position + length]
        self.position += length + 1

        return bytearray(buffer).decode('949')

    def read_string16(self):
        if self.position + 2 > len(self.data):
            return ""

        length = self.data[self.position] << 8 | self.data[self.position + 1]
        position = self.position + 2

        if position + length > len(self.data):
            return ""

        buffer = self.data[position:position + length]
        self.position += length + 2

        return bytearray(buffer).decode('949')

    def decrypt(self, crypto):
        key = ""
        length = len(self.data) - 3

        rand_16 = uint16((self.data[length + 2] << 8 | self.data[length]) ^ 0x6474)
        rand_8 = uint8(self.data[length + 1] ^ 0x24)

        if self.encrypt_method == EncryptMethod.Normal:
            key = crypto.key
        elif self.encrypt_method == EncryptMethod.MD5Key:
            key = crypto.generate_key(rand_16, rand_8)
        else:
            return

        for i in range(0, length):
            salt_index = (i / len(crypto.key)) % 256

            self.data[i] ^= uint8(crypto.salt[salt_index] ^ ord(key[i % len(key)]))

            if salt_index != self.ordinal:
                self.data[i] ^= crypto.salt[self.ordinal]

        self.data = self.data[:length]


class EncryptMethod:
    NoEncrypt = 0
    Normal = 1
    MD5Key = 2


class PacketSeekOrigin:
    Begin = 0
    Current = 1
    End = 2
