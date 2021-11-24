import json
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

    def read_between(self, start, end):
        out = self.data[start:end]
        return out

    def read_to_end(self):
        out = self.data[self.position:]
        self.position = self.size
        return out

    def reset_position(self):
        self.position = 0

    def set_position(self, position):
        self.position = position

    def get_position(self):
        return self.position


parser = ArgumentParser()
parser.add_argument("-f", "--file", dest="filename",
                    help="read from firmware file", metavar="FILE")
args = parser.parse_args()

if args.filename == None or os.path.exists(args.filename) == False:
    print("no file found")
else:
    path, file = os.path.split(os.path.abspath(args.filename))
    basename = os.path.splitext(file)[0]

    #rc4data = bytes.fromhex("954494873DBF65CA20018B21290256B5B8797232230C7B76544C5222DA5548F8D6702B808EB0D23FC64A0BC3C99B68EF61AED781D366759ABCE8AB5C4E89C71DACAAE06469179262F640FDC5580FFEB43EA235F37F31CEEB574F4573416FD593E6B211DDB991FF90056EFCBAA99E26E906E33C1571B31A5025141C42125DA5E5992D8FA88D963413A446DCCCA6CFA0C20349D05A84F124282F9839477CD8A15FAD095EEDC47E60DEA76AD1F4DBCD4BB72C1E9C27E183C0FA0A512A30EE9D53F57D7A19D9E2CB4D826DF9D400BBEA0D10E71F373A67F0851BFB6CBEEC865B8808DF36C8779FAFE4B18C97072E74383BBDF2436316F7338A780EA3046B1859C1B6")
    key = bytes.fromhex("f16d3357025e174fbe8f895bd1798062096750966c51f853")

    with open(file, "r+b") as f:
        file = bytes(f.read())

        bs = BinSeeker(file)
        data = bs.read_between(0, bs.size-16)
        hash_calculated = MD5.new(data).hexdigest().upper()
        temp = bs.read_between(bs.size-16, bs.size)
        hash_embedded = ''.join(f'{n:02x}' for n in temp).upper()
        flag_hashesmatch = hash_embedded == hash_calculated

        if flag_hashesmatch:
            bs.reset_position()
            temp = bs.read_next_bytes(8)
            firmware_size = int(np.frombuffer(temp, np.uint64))
            firmware = bs.read_next_bytes(firmware_size)
            temp = bs.read_next_bytes(8)
            pic = temp

            rc4 = ARC4.new(key)
            decrypted_fw = bytes(rc4.decrypt(firmware))
            bs_fw_decrypted = BinSeeker(decrypted_fw)
            # create array for checksum calculation
            arr = bytes(bs_fw_decrypted.size - 4)
            arr = bs_fw_decrypted.read_between(0, bs_fw_decrypted.size - 4)
            checksum_calculated = crc32(arr)
            # read firmware field for checksum
            arr = bytes(4)
            arr = bs_fw_decrypted.read_between(
                bs_fw_decrypted.size-4, bs_fw_decrypted.size)
            checksum_embedded = np.uint((int(arr[0]) << 24) + (int(arr[1])
                                                               << 16) + (int(arr[2]) << 8) + int(arr[3]))
            flag_checksum_match = checksum_calculated == checksum_embedded
            if flag_checksum_match:
                # create array for product info
                arr = bytes(16)
                bs_fw_decrypted.reset_position()
                # read firmware field for productType
                arr = bs_fw_decrypted.read_next_bytes(16)
                productType = ''.join(chr(i) for i in arr)
                # read firmware field for softVersion
                arr = bs_fw_decrypted.read_next_bytes(16)
                softVersion = ''.join(chr(i) for i in arr)
                # read firmware field for hwVersion
                arr = bs_fw_decrypted.read_next_bytes(16)
                hwVersion = ''.join(chr(i) for i in arr)
                # create array for product info
                arr = bytes(32)
                # read firmware field for GenerateTime
                arr = bs_fw_decrypted.read_next_bytes(32)
                GenerateTime = ''.join(chr(i) for i in arr)

                # create array for product info
                arr = bytes(32)
                # read firmware field for appcode length
                arr = bs_fw_decrypted.read_next_bytes(4)
                len = np.uint((int(arr[0]) << 24) + (int(arr[1])
                              << 16) + (int(arr[2]) << 8) + int(arr[3]))
                # read firmware field for startAddr
                arr = bs_fw_decrypted.read_next_bytes(4)
                startAddr = np.uint(
                    (int(arr[0]) << 24) + (int(arr[1]) << 16) + (int(arr[2]) << 8) + int(arr[3]))
                # read firmware field for appdata_checksum
                arr = bs_fw_decrypted.read_next_bytes(4)
                appcode_checksum_embedded = np.uint((int(arr[0]) << 24) + (int(arr[1])
                                                                           << 16) + (int(arr[2]) << 8) + int(arr[3]))
                # create array for appcode
                arr = bytes(len)
                # read appcode
                appcode = bs_fw_decrypted.read_next_bytes(len)

                appcode_checksum_calculated = crc32(appcode)
                flag_checksum_appcode_match = appcode_checksum_embedded == appcode_checksum_calculated

                if flag_checksum_appcode_match:
                    export = {"hash_calculated": str(hash_calculated), "hash_embedded": str(hash_embedded), "checksum_calculated": str(checksum_calculated), "checksum_embedded": str(checksum_embedded), "productType": str(productType),
                              "softVersion": str(softVersion), "hwVersion": str(hwVersion), "GenerateTime": str(GenerateTime), "appdata_checksum_embedded": str(appcode_checksum_embedded), "appdata_checksum_calculated": str(appcode_checksum_calculated)}
                    with open(path + '\\' + basename + '_report.json', 'w', encoding='utf-8') as f:
                        json.dump(export, f, ensure_ascii=False, indent=4)

                    with open(path + '\\' + basename + '_00_firmware_encryped.bin', "w+b") as fw:
                        fw.write(firmware)
                        fw.close()
                    with open(path + '\\' + basename + '_00_pic.bin', "w+b") as picture:
                        picture.write(pic)
                        picture.close()
                    with open(path + '\\' + basename + '_01_firmware_decrypted.bin', "w+b") as fwd:
                        fwd.write(decrypted_fw)
                        fwd.close()
                    with open(path + '\\' + basename + '_02_appdata_decrypted.bin', "w+b") as add:
                        add.write(appcode)
                        add.close()
                else:
                    print(
                        "ERROR: checksum from appcode does not match embedded checksum")
            else:
                print(
                    "ERROR: checksum from decrypted firmware part does not match embedded checksum")
        else:
            print("ERROR: hash from file does not match firmware hash")

    f.close()
    print("SUCCESS: export successful. exiting")
