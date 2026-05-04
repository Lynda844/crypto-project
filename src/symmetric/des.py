"""
DES (Data Encryption Standard) - Implémentation Python pure
Clé 64 bits (56 bits effectifs), bloc 64 bits
"""

# ─── Tables de permutation DES ────────────────────────────────────────────────

IP = [
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7,
]
IP_INV = [
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41, 9,49,17,57,25,
]
PC1 = [
    57,49,41,33,25,17, 9,  1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27, 19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15,  7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29, 21,13, 5,28,20,12, 4,
]
PC2 = [
    14,17,11,24, 1, 5, 3,28, 15, 6,21,10,
    23,19,12, 4,26, 8, 16, 7,27,20,13, 2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32,
]
E = [
    32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32, 1,
]
P = [
    16, 7,20,21, 29,12,28,17,
     1,15,23,26,  5,18,31,10,
     2, 8,24,14, 32,27, 3, 9,
    19,13,30, 6, 22,11, 4,25,
]
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

SBOXES = [
    # S1
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
      0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
      4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
     15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    # S2
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
      3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
      0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
     13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    # S3
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
     13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
     13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
      1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    # S4
    [ 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
     13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
     10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
      3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    # S5
    [ 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
     14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
      4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
     11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    # S6
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
     10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
      9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
      4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    # S7
    [ 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
     13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
      1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
      6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    # S8
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
      1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
      7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
      2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]

# ─── Utilitaires bits ─────────────────────────────────────────────────────────

def permute(bits, table):
    return [bits[t-1] for t in table]

def int_to_bits(n, length):
    return [(n >> (length-1-i)) & 1 for i in range(length)]

def bits_to_int(bits):
    n = 0
    for b in bits:
        n = (n << 1) | b
    return n

def bytes_to_bits(data: bytes):
    bits = []
    for byte in data:
        bits.extend(int_to_bits(byte, 8))
    return bits

def bits_to_bytes(bits) -> bytes:
    assert len(bits) % 8 == 0
    return bytes(bits_to_int(bits[i:i+8]) for i in range(0, len(bits), 8))

# ─── Génération des sous-clés ─────────────────────────────────────────────────

def generate_subkeys(key: bytes):
    assert len(key) == 8, "Clé DES : 8 octets (64 bits)"
    key_bits = bytes_to_bits(key)
    key56 = permute(key_bits, PC1)      # 56 bits
    C, D = key56[:28], key56[28:]

    subkeys = []
    for shift in SHIFTS:
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        CD = C + D
        subkeys.append(permute(CD, PC2))  # 48 bits
    return subkeys

# ─── Fonction F ───────────────────────────────────────────────────────────────

def f_function(R, subkey):
    # Expansion E : 32 → 48 bits
    expanded = permute(R, E)
    # XOR avec sous-clé
    xored = [expanded[i] ^ subkey[i] for i in range(48)]
    # S-Boxes : 48 → 32 bits
    sbox_out = []
    for s in range(8):
        chunk = xored[s*6:(s+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = bits_to_int(chunk[1:5])
        val = SBOXES[s][row * 16 + col]
        sbox_out.extend(int_to_bits(val, 4))
    # Permutation P
    return permute(sbox_out, P)

# ─── Chiffrement / Déchiffrement d'un bloc ───────────────────────────────────

def des_block(block: bytes, subkeys) -> bytes:
    assert len(block) == 8
    bits = bytes_to_bits(block)
    bits = permute(bits, IP)
    L, R = bits[:32], bits[32:]

    for i in range(16):
        f_out = f_function(R, subkeys[i])
        L, R = R, [L[j] ^ f_out[j] for j in range(32)]

    combined = permute(R + L, IP_INV)
    return bits_to_bytes(combined)

# ─── Padding PKCS#7 ───────────────────────────────────────────────────────────

def pkcs7_pad(data: bytes, bs=8) -> bytes:
    pad = bs - len(data) % bs
    return data + bytes([pad] * pad)

def pkcs7_unpad(data: bytes) -> bytes:
    return data[:-data[-1]]

# ─── Interface principale ─────────────────────────────────────────────────────

class DES:
    def __init__(self, key: bytes):
        self.subkeys = generate_subkeys(key)
        self.subkeys_inv = list(reversed(self.subkeys))

    def encrypt(self, plaintext: bytes) -> bytes:
        padded = pkcs7_pad(plaintext)
        ct = b""
        for i in range(0, len(padded), 8):
            ct += des_block(padded[i:i+8], self.subkeys)
        return ct

    def decrypt(self, ciphertext: bytes) -> bytes:
        pt = b""
        for i in range(0, len(ciphertext), 8):
            pt += des_block(ciphertext[i:i+8], self.subkeys_inv)
        return pkcs7_unpad(pt)


# ─── Tests ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("TEST DES - Vecteur NIST")
    print("=" * 60)

    # Vecteur standard DES : FIPS PUB 81
    key    = bytes.fromhex("133457799BBCDFF1")
    block  = bytes.fromhex("0123456789ABCDEF")
    expected = bytes.fromhex("85E813540F0AB405")

    subkeys = generate_subkeys(key)
    ct = des_block(block, subkeys)
    print(f"Plaintext  : {block.hex().upper()}")
    print(f"Key        : {key.hex().upper()}")
    print(f"Ciphertext : {ct.hex().upper()}")
    print(f"Attendu    : {expected.hex().upper()}")
    print(f"✓ NIST OK  : {ct == expected}")

    # Déchiffrement
    subkeys_inv = list(reversed(subkeys))
    pt = des_block(ct, subkeys_inv)
    print(f"Déchiffré  : {pt.hex().upper()}")
    print(f"✓ Inverse  : {pt == block}")

    print()
    print("=" * 60)
    print("TEST DES - Message texte")
    print("=" * 60)

    key2 = b"MonCle8B"  # 8 octets
    msg  = b"Hello DES World!"
    des  = DES(key2)

    ct2 = des.encrypt(msg)
    pt2 = des.decrypt(ct2)
    print(f"Message    : {msg}")
    print(f"Chiffré    : {ct2.hex()}")
    print(f"Déchiffré  : {pt2}")
    print(f"✓ Résultat : {pt2 == msg}")

    print()
    print("=" * 60)
    print("TEST DES - Messages de longueurs variées")
    print("=" * 60)

    des3 = DES(b"TestKey!")
    for msg in [b"A", b"Bonjour", b"Message de 16 B!", b"Un message plus long que 16 octets exactement"]:
        assert des3.decrypt(des3.encrypt(msg)) == msg
        print(f"✓ '{msg.decode()}' OK")

