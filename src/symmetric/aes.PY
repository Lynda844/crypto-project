"""
AES (Advanced Encryption Standard) - Implémentation Python pure
Supporte AES-128, AES-192, AES-256
"""

# ─── S-Box et tables AES ──────────────────────────────────────────────────────

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

# ─── Fonctions GF(2^8) ────────────────────────────────────────────────────────

def xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = xtime(a)
        b >>= 1
    return p

# ─── Key Expansion ────────────────────────────────────────────────────────────

def key_expansion(key: bytes):
    key_len = len(key)
    assert key_len in (16, 24, 32), "Clé AES : 16, 24 ou 32 octets"
    nk = key_len // 4
    nr = nk + 6  # rounds

    w = [list(key[4*i:4*i+4]) for i in range(nk)]

    for i in range(nk, 4 * (nr + 1)):
        temp = w[i-1][:]
        if i % nk == 0:
            temp = [SBOX[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        w.append([w[i-nk][j] ^ temp[j] for j in range(4)])

    return w, nr

# ─── State helpers ────────────────────────────────────────────────────────────

def bytes_to_state(block: bytes):
    return [[block[r + 4*c] for c in range(4)] for r in range(4)]

def state_to_bytes(state) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))

def add_round_key(state, w, round_num):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= w[round_num*4 + c][r]

# ─── Transformations ──────────────────────────────────────────────────────────

def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]

def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]

def shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]

def inv_shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]

def mix_columns(state):
    for c in range(4):
        s = [state[r][c] for r in range(4)]
        state[0][c] = gmul(0x02,s[0])^gmul(0x03,s[1])^s[2]^s[3]
        state[1][c] = s[0]^gmul(0x02,s[1])^gmul(0x03,s[2])^s[3]
        state[2][c] = s[0]^s[1]^gmul(0x02,s[2])^gmul(0x03,s[3])
        state[3][c] = gmul(0x03,s[0])^s[1]^s[2]^gmul(0x02,s[3])

def inv_mix_columns(state):
    for c in range(4):
        s = [state[r][c] for r in range(4)]
        state[0][c] = gmul(0x0e,s[0])^gmul(0x0b,s[1])^gmul(0x0d,s[2])^gmul(0x09,s[3])
        state[1][c] = gmul(0x09,s[0])^gmul(0x0e,s[1])^gmul(0x0b,s[2])^gmul(0x0d,s[3])
        state[2][c] = gmul(0x0d,s[0])^gmul(0x09,s[1])^gmul(0x0e,s[2])^gmul(0x0b,s[3])
        state[3][c] = gmul(0x0b,s[0])^gmul(0x0d,s[1])^gmul(0x09,s[2])^gmul(0x0e,s[3])

# ─── Chiffrement / Déchiffrement d'un bloc ───────────────────────────────────

def aes_encrypt_block(block: bytes, w, nr) -> bytes:
    state = bytes_to_state(block)
    add_round_key(state, w, 0)
    for rnd in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, w, rnd)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, w, nr)
    return state_to_bytes(state)

def aes_decrypt_block(block: bytes, w, nr) -> bytes:
    state = bytes_to_state(block)
    add_round_key(state, w, nr)
    for rnd in range(nr-1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, w, rnd)
        inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, w, 0)
    return state_to_bytes(state)

# ─── Padding PKCS#7 ───────────────────────────────────────────────────────────

def pkcs7_pad(data: bytes, block_size=16) -> bytes:
    pad = block_size - len(data) % block_size
    return data + bytes([pad] * pad)

def pkcs7_unpad(data: bytes) -> bytes:
    pad = data[-1]
    return data[:-pad]

# ─── Interface principale (ECB) ───────────────────────────────────────────────

class AES:
    def __init__(self, key: bytes):
        self.w, self.nr = key_expansion(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        padded = pkcs7_pad(plaintext)
        ct = b""
        for i in range(0, len(padded), 16):
            ct += aes_encrypt_block(padded[i:i+16], self.w, self.nr)
        return ct

    def decrypt(self, ciphertext: bytes) -> bytes:
        pt = b""
        for i in range(0, len(ciphertext), 16):
            pt += aes_decrypt_block(ciphertext[i:i+16], self.w, self.nr)
        return pkcs7_unpad(pt)


# ─── Tests ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("TEST AES-128")
    print("=" * 60)

    # Vecteur NIST FIPS-197 Appendix B
    key   = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    block = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    expected = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

    w, nr = key_expansion(key)
    ct = aes_encrypt_block(block, w, nr)
    print(f"Plaintext  : {block.hex()}")
    print(f"Key        : {key.hex()}")
    print(f"Ciphertext : {ct.hex()}")
    print(f"Attendu    : {expected.hex()}")
    print(f"✓ NIST OK  : {ct == expected}")

    pt = aes_decrypt_block(ct, w, nr)
    print(f"Déchiffré  : {pt.hex()}")
    print(f"✓ Inverse  : {pt == block}")

    print()
    print("=" * 60)
    print("TEST AES-256 + message texte")
    print("=" * 60)

    key256 = b"cle256bits_32oct_cle256bits_32o!"  # 32 octets
    msg    = b"Hello AES-256 World!"
    aes    = AES(key256)

    ct2 = aes.encrypt(msg)
    pt2 = aes.decrypt(ct2)
    print(f"Message    : {msg}")
    print(f"Chiffré    : {ct2.hex()}")
    print(f"Déchiffré  : {pt2}")
    print(f"✓ Résultat : {pt2 == msg}")

    print()
    print("=" * 60)
    print("TEST AES-128 / 192 / 256 - longueurs de clés")
    print("=" * 60)
    for klen in [16, 24, 32]:
        key_t = bytes(range(klen))
        a = AES(key_t)
        data = b"Test crypto AES!"
        assert a.decrypt(a.encrypt(data)) == data
        print(f"✓ AES-{klen*8} OK")
