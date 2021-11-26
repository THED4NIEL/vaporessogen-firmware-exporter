# vaporessogen-firmware-exporter
decrypts and exports Vaporesso GEN firmware files (supports GEN, GEN S, GEN X firmware)

# usage
./firmware_decoder.py -f path_to_firmware_file.bin

# output 
#### BASENAME_00_firmware_encrypted.bin

contains the encrypted firmware part

#### BASENAME_00_config_encrypted.bin

contains the encrypted config part for the device

#### BASENAME_01_firmware_decrypted.bin

contains the decrypted firmware part

#### BASENAME_01_config_decrypted.bin

contains the decrypted config part for the device
