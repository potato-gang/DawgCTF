#!/usr/bin/env python3

import socket

# You can easily leak that
IV = b'p]\xb2\x97\x15\x9cK\xaf!\xd6\x82_N\xe2]]'

# The flag split up in 16 byte blocks
blocks = [
    IV,
    b"\xe7\x10\x98\x8f_\xb3Zi#8[2\xd4\x8a'-",
    b"\xf8\xf3\xa2\x96&\xfc}\x8a\xb0\x8d\xd7\x17_\nR!",
    b".\xb5\x80\xf4\x16\x9e Us\x10\n\xc7\xa8bE\xfc"
]

# This will hold the plaintext flag
decrypted = b""

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1.5)
sock.connect(('crypto.ctf.umbccd.io', 13372))


for i in range(1, len(blocks)): # decrypt all blocks of the flag
    modified_last_block = bytearray(blocks[i - 1])
    clear = None

    # Bruteforce all possible values
    for last_byte in range(256):        
        modified_last_block[-1] = last_byte  # modifies last byte of C1
        
        sock.send(b"dec:" + IV + modified_last_block + blocks[i])
        
        # If the padding is invalid the server doesn't respond
        # which would cause recv() to block indefinitely so
        # here we just wait 1.5 seconds for an answer
        try:
            clear = sock.recv(1024)
        except socket.timeout:
            continue
        
        # We need exactly one byte of padding!
        if len(clear) != 16 + 15:
            continue
            
        clear = clear[16:] + bytes([ (last_byte ^ 1) ^ blocks[i - 1][-1] ])
        break
    else:
        raise RuntimeError("nothing found")

    decrypted += clear
    
sock.close()
print(decrypted)
