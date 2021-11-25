import os
import numpy as np
from binascii import crc32
from Crypto.Cipher import ARC4
from Crypto.Hash import MD5, SHA
from Crypto.Random import get_random_bytes
from argparse import ArgumentParser


class BinSeeker:
    def __init__(self, data=bytes()):
        self.position = 0
        self.data = bytes(data)
        c = 0
        for x in data:
            c = c + 1
        self.size = c

    def read_next_bytes(self, number_of_bytes):
        out = self.data[self.position:self.position+number_of_bytes]
        self.position += number_of_bytes
        return out

    def reset_position(self):
        self.position = 0

    def set_position(self, position):
        self.position = position

    def get_position(self):
        return self.position


class FirmwareData:
    def __init__(self, productName="", softVersion="", hwVersion="", GenerateTime="", len=0, startAddr=0, data=bytes()):
        self.productName = productName
        self.softVersion = softVersion
        self.hwVersion = hwVersion
        self.GenerateTime = GenerateTime
        self.len = len
        self.startAddr = startAddr
        self.data = bytes(data)


def decrypt(input_data):
    key = bytes.fromhex("f16d3357025e174fbe8f895bd1798062096750966c51f853")
    rc4 = ARC4.new(key)

    decrypted = bytes(rc4.decrypt(input_data))
    bs = BinSeeker(decrypted)
    bs.reset_position()
    # create array for checksum calculation
    arr = bytes(bs.size - 4)
    arr = bs.read_next_bytes(bs.size - 4)
    checksum_calculated = crc32(arr)
    # read firmware field for checksum
    arr = bytes(4)
    arr = bs.read_next_bytes(4)
    checksum_embedded = np.uint((int(arr[0]) << 24) + (int(arr[1])
                                                       << 16) + (int(arr[2]) << 8) + int(arr[3]))
    flag_checksum_match = checksum_calculated == checksum_embedded
    if flag_checksum_match:
        bs.reset_position()
        # create array for product info
        arr = bytes(16)
        # read firmware field for productType
        arr = bs.read_next_bytes(16)
        productName = arr.replace(b'\x00', b'').decode('ascii')
        # read firmware field for softVersion
        arr = bs.read_next_bytes(16)
        softVersion = arr.replace(b'\x00', b'').decode('ascii')
        # read firmware field for hwVersion
        arr = bs.read_next_bytes(16)
        hwVersion = arr.replace(b'\x00', b'').decode('ascii')
        # create array for product info
        arr = bytes(32)
        # read firmware field for GenerateTime
        arr = bs.read_next_bytes(32)
        GenerateTime = arr.replace(b'\x00', b'').decode('ascii')
        # create array for product info
        arr = bytes(32)
        # read firmware field for code length
        arr = bs.read_next_bytes(4)
        len = np.uint((int(arr[0]) << 24) + (int(arr[1])
                      << 16) + (int(arr[2]) << 8) + int(arr[3]))
        # read firmware field for startAddr
        arr = bs.read_next_bytes(4)
        startAddr = np.uint(
            (int(arr[0]) << 24) + (int(arr[1]) << 16) + (int(arr[2]) << 8) + int(arr[3]))
        # read firmware field for checksum
        arr = bs.read_next_bytes(4)
        checksum_embedded = np.uint((int(arr[0]) << 24) + (int(arr[1])
                                                           << 16) + (int(arr[2]) << 8) + int(arr[3]))
        # create array for appcode
        arr = bytes(len)
        # read appcode
        data = bs.read_next_bytes(len)
        checksum_calculated = crc32(data)
        flag_checksum_match = checksum_embedded == checksum_calculated
        if flag_checksum_match:
            return FirmwareData(productName, softVersion,
                                hwVersion, GenerateTime, len, startAddr, data)
        else:
            print("ERROR: checksum from codepart does not match embedded checksum")
            return FirmwareData()
    else:
        print(
            "ERROR: checksum from decrypted firmware part does not match embedded checksum")
    return FirmwareData()


'''

START PROGRAM

'''
parser = ArgumentParser()
parser.add_argument("-f", "--file", dest="filename",
                    help="read from firmware file", metavar="FILE")
args = parser.parse_args()

# for debug purpose
args.filename = ".\\firmware.bin"

if args.filename == None or os.path.exists(args.filename) == False:
    print("no file found")
else:
    path, file = os.path.split(os.path.abspath(args.filename))
    basename = os.path.splitext(file)[0]

    f = open(file, "r+b")
    file = bytes(f.read())
    f.close

    dat = bytes()

    bs = BinSeeker(file)
    bs.reset_position()
    data = bs.read_next_bytes(bs.size-16)
    hash_calculated = MD5.new(data).hexdigest().upper()
    temp = bs.read_next_bytes(16)
    hash_embedded = ''.join(f'{n:02x}' for n in temp).upper()
    flag_hashesmatch = hash_embedded == hash_calculated

    if flag_hashesmatch:
        bs.reset_position()
        temp = bs.read_next_bytes(8)
        firmware_size = int(np.frombuffer(temp, np.uint64))
        firmware = bs.read_next_bytes(firmware_size)
        temp = bs.read_next_bytes(8)
        pic_size = int(np.frombuffer(temp, np.uint64))
        pic = bs.read_next_bytes(pic_size)

        with open(path + '\\' + basename + '_00_firmware_encryped.bin', "w+b") as fw:
            fw.write(firmware)
            fw.close()
        with open(path + '\\' + basename + '_01_pic_encrypted.bin', "w+b") as p:
            p.write(pic)
            p.close()

        firmware_decrypted = decrypt(firmware)
        if not firmware_decrypted.len == 0:
            with open(path + '\\' + basename + '_00_firmware_decryped.bin', "w+b") as fw:
                fw.write(firmware_decrypted.data)
                fw.close()

        pic_decrypted = decrypt(pic)
        if not pic_decrypted.len == 0:
            with open(path + '\\' + basename + '_01_pic_decrypted.bin', "w+b") as p:
                p.write(pic_decrypted.data)
                p.close()

        print("finished")

    else:
        print("ERROR: hash from encrypted firmware part does not match embedded hash")
