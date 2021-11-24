# vaporessogen-firmware-exporter
decrypts and exports vaporesso gen firmware files

# usage
./firmware_decoder.py -f path_to_firmware_file.bin

# output 
### BASENAME_report.json 

contains checksums for firmware parts, informations about product type, firmware version, hardware version and creation time of the firmware

### BASENAME_00_firmware_encrypted.bin

contains the encrypted firmware part from the file without additional data

### BASENAME_00_pic.bin

TBD

### BASENAME_01_firmware_decrypted.bin

contains the decrypted firmware part

### BASENAME_02_firmware_encrypted.bin

contains the decrypted appcode part from the firmware
