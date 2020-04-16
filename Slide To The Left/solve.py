#!/usr/bin/env python3

import socket

# You can easily leak that
IV =   b'\x94\xd0g\xa3e\xb5\x1d\xa0X\x9f\x8b\xa2\xeeg\xfd\xd6'

# The individual blocks of the encrypted flag
blocks = [
    IV,
    b'z\x8d4A\xfd<\'\x8d4\xf0\xaf\xef]\xb6\xd2\x88',
    b'\x1b\x1b\xce\x9b\xa1\xb4\xf5!\xd3M\xcf*Ge\x15\x04',
    b'\xfb$\xa5\x18\x1d\xef?\xea\xbe\xa8/U\x88\xe70\xa9',
    b'E\x8a\xd7@\xe3\nl\xa3\xcb\xa7\xd00\x17\x9ew\x99',
    b'U\x90\xb7\xe8u\xc2\xbf:\x0e\xa8\xf5"\x83\x0f\xe0\xa3',
    b'$\xb3I\x03\x11\xfd\xcbc\xd6cE\x85\xad\xb2K\x07'
]

# Will hold decrypted flag
decrypted = b""

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1.5)
sock.connect(('crypto.ctf.umbccd.io', 13373))

for i in range(1, len(blocks)): # decrypt block by block
    modified_last_block = bytearray(blocks[i - 1])
    clear = None

    # Bruteforce possible values
    for last_byte in range(256):
        modified_last_block[-1] = last_byte  # modify last byte of C1
        
        sock.send(b"dec:" + IV + modified_last_block + blocks[i])
        
        # check if padding is valid (answer comes immediately)
        try:
            clear = sock.recv(1024)
        except socket.timeout:
            continue
            
        # Padding needs to be exactly 1
        if len(clear) != 16 + 15:
            continue
            
        clear = clear[16:] + bytes([ (last_byte ^ 1) ^ blocks[i - 1][-1] ])
        break
    else:
        raise RuntimeError("nothing found")

    decrypted += clear
    print(decrypted)
    
sock.close()
