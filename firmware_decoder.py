import os
from binascii import crc32
from argparse import ArgumentParser

# Package: PYCRYPTODOME
from Crypto.Cipher import ARC4
from Crypto.Hash import MD5


class BinSeeker:
    def __init__(self, data=bytes()):
        self.position = 0
        self.data = bytes(data)
        self.size = len(data)

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
    def __init__(self, productName='', softVersion='', hwVersion='', GenerateTime='', len=0, startAddr=0, data=bytes()):
        self.productName = productName
        self.softVersion = softVersion
        self.hwVersion = hwVersion
        self.GenerateTime = GenerateTime
        self.len = len
        self.startAddr = startAddr
        self.data = bytes(data)


def decrypt(input_data):
    # initialize decryption
    rc4 = ARC4.new(
        b'\xf1\x6d\x33\x57\x02\x5e\x17\x4f\xbe\x8f\x89\x5b\xd1\x79\x80\x62\x09\x67\x50\x96\x6c\x51\xf8\x53')

    # decrypt firmware
    decrypted = bytes(rc4.decrypt(input_data))

    # create a new instance of BinSeeker for reading
    bs = BinSeeker(decrypted)
    bs.reset_position()

    # calculate checksum for decrypted firmware
    tmp_fw = bs.read_next_bytes(bs.size - 4)
    checksum_calculated = crc32(tmp_fw)

    # read firmware field for checksum
    cs_tmp = bs.read_next_bytes(4)
    checksum_embedded = int.from_bytes(
        cs_tmp, byteorder='big', signed=False)

    # verify checksum for decrypted firmware
    flag_checksum_match = checksum_calculated == checksum_embedded
    if flag_checksum_match:
        # reset BinSeeker position
        bs.reset_position()

        # read firmware field for productType
        productName = bs.read_next_bytes(
            16).replace(b'\x00', b'').decode('ascii')

        # read firmware field for softVersion
        softVersion = bs.read_next_bytes(
            16).replace(b'\x00', b'').decode('ascii')

        # read firmware field for hwVersion
        hwVersion = bs.read_next_bytes(16).replace(
            b'\x00', b'').decode('ascii')

        # read firmware field for GenerateTime
        GenerateTime = bs.read_next_bytes(
            32).replace(b'\x00', b'').decode('ascii')

        # read firmware field for code length
        len_tmp = bs.read_next_bytes(4)
        firmware_length = int.from_bytes(
            len_tmp, byteorder='big', signed=False)

        # read firmware field for startAddr
        saddr_tmp = bs.read_next_bytes(4)
        startAddr = int.from_bytes(
            saddr_tmp, byteorder='big', signed=False)

        # read firmware field for checksum
        cs_tmp = bs.read_next_bytes(4)
        checksum_embedded = int.from_bytes(
            cs_tmp, byteorder='big', signed=False)

        # read appcode
        data = bs.read_next_bytes(firmware_length)

        # calculate checksum for appcode
        checksum_calculated = crc32(data)

        # verify checksum of appcode
        flag_checksum_match = checksum_embedded == checksum_calculated
        if flag_checksum_match:
            return FirmwareData(productName, softVersion,
                                hwVersion, GenerateTime, firmware_length, startAddr, data)
        else:
            print('ERROR: checksum from codepart does not match embedded checksum')
            return FirmwareData()
    else:
        print(
            'ERROR: checksum from decrypted firmware part does not match embedded checksum')
    return FirmwareData()


'''

START PROGRAM

'''
parser = ArgumentParser()
parser.add_argument('-f', '--file', dest='filename',
                    help='read from firmware file', metavar='FILE')
parser.add_argument('-d', '--debug', dest='debug',
                    help='set debug mode', action='store_true')
args = parser.parse_args()

# for debug purpose
if args.debug == True:
    args.filename = os.path.join('.', 'firmware.bin')

if args.filename == None or os.path.exists(args.filename) == False:
    print('no file found')
else:
    path, file = os.path.split(os.path.abspath(args.filename))
    basename = os.path.splitext(file)[0]

    # read upgrade package
    with open(file, 'r+b') as f:
        file = bytes(f.read())

    # create new instance of BinSeeker
    bs = BinSeeker(file)
    bs.reset_position()

    # read upgrade package
    data = bs.read_next_bytes(bs.size-16)

    # calculate hash from upgrade package
    hash_calculated = MD5.new(data).hexdigest().upper()

    # read hash from upgrade package
    temp = bs.read_next_bytes(16)
    hash_embedded = ''.join(f'{n:02x}' for n in temp).upper()

    # verify hash for upgrade package
    flag_hashesmatch = hash_embedded == hash_calculated
    if flag_hashesmatch:
        # reset BinSeeker position
        bs.reset_position()

        # read firmware
        temp = bs.read_next_bytes(8)
        firmware_size = int.from_bytes(temp, byteorder='little', signed=False)
        firmware = bs.read_next_bytes(firmware_size)

        # read firmware configuration
        temp = bs.read_next_bytes(8)
        config_size = int.from_bytes(temp, byteorder='little', signed=False)
        config = bs.read_next_bytes(config_size)
        with open(os.path.join(path, basename + '_00_firmware_encryped.bin'), 'w+b') as fw:
            fw.write(firmware)
        with open(os.path.join(path, basename + '_01_config_encrypted.bin'), 'w+b') as p:
            p.write(config)

        firmware_decrypted = decrypt(firmware)
        if not firmware_decrypted.len == 0:
            with open(os.path.join(path, basename + '_00_firmware_decryped.bin'), 'w+b') as fw:
                fw.write(firmware_decrypted.data)

        config_decrypted = decrypt(config)
        if not config_decrypted.len == 0:
            with open(os.path.join(path, basename + '_01_config_decrypted.bin'), 'w+b') as p:
                p.write(config_decrypted.data)

        print('finished')

    else:
        print('ERROR: hash from encrypted firmware part does not match embedded hash')
