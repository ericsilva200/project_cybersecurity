import os
import crypto
import yara_scan

def main(file_name):
    yara_scan.scan_file(file_name)
    crypto.encrypt_file(file_name)

# main("test.txt")
# main("image.png")
# main("eicar.com")
main("image.pdf")