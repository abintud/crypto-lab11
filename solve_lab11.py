# Lab 11 - Encrypted Evidence File (Challenge Lab)
# Secure Communication and Cryptography - MACS H6014
#
# Reverse-engineered from the recovered encryptme.py:
#   step1 = ROT13            (its own inverse)
#   step2 = base64 encode    (reverse = base64 decode)
#   step3 = Caesar +4 on lowercase letters (reverse = shift -4)

import base64, string, codecs

def rot13(s):                       # reverse of step1 (and step1 itself)
    return codecs.encode(s, 'rot_13')

def caesar_back(s, shift=4):        # reverse of step3
    lower = string.ascii_lowercase
    shifted = lower[shift:] + lower[:shift]
    return s.translate(str.maketrans(shifted, lower))

def decode(cipher):
    s = cipher.strip()
    steps = []
    while s and s[0] in '123':
        tag, rest = s[0], s[1:]
        if tag == '1':
            s = rot13(rest); steps.append('ROT13')
        elif tag == '3':
            s = caesar_back(rest); steps.append('Caesar -4')
        elif tag == '2':
            dec = base64.b64decode(rest)
            try:
                s = dec.decode('utf-8')
            except UnicodeDecodeError:
                s = dec.decode('latin-1')
            steps.append('base64 decode')
            if not (s and s[0] in '123'):   # reached the plaintext
                break
    return s, steps

if __name__ == '__main__':
    import sys
    cipher = sys.argv[1] if len(sys.argv) > 1 else open('intercepted.txt').read()
    msg, steps = decode(cipher)
    print("Number of layers peeled:", len(steps))
    print("Decoded message:")
    print(msg)
