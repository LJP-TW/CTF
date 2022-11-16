from Crypto.Cipher import ARC4

# ARC4 key
key = b'PyArmor_Pr0tecteth_My_K3y'

# encoded = base64.encode(s)
s = b'\xfc\x1d\xc4>\xeadS\x9c\xb6\x18A\xf2k,?,\xfd\xb9\x81\xde\x8et%Ua\xe8^\xf8z\xa7\xca\x1c$\x11\x93\xf6h,b\x8ebd\x05\xc6\xf9\x14'
encoded = b'/B3EPupkU5y2GEHyayw/LP25gd6OdCVVYehe+HqnyhwkEZP2aCxijmJkBcb5FA=='

cipher = ARC4.new(key)
s = cipher.encrypt(s)

print(s)

# Pyth0n_Prot3ction_tuRn3d_Up_t0_11@flare-on.com