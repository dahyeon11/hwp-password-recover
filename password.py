import hashlib

def genkey(pwd):
    buf = bytearray(160)
    # Convert string to bytes if needed
    if isinstance(pwd, str):
        password = bytearray(pwd.encode('utf-8'))
    else:
        password = bytearray(pwd)

    for i in range(0, len(password)):
        if i:
            v6 = password[i-1]
        else:
            v6 = 0xec

        v7 = (2 * v6 | (v6 >> 7)) & 0xff

        buf[i*2] = v7
        buf[i*2+1] = password[i]

    sha1 = hashlib.sha1()
    sha1.update(bytes(buf).replace(b"\x00", b""))
    h = sha1.hexdigest()

    return bytes.fromhex(h[:32])
