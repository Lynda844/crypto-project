"""
RC4 (Rivest Cipher 4) - Implémentation Python pure
Chiffrement par flot symétrique (stream cipher)
Clé variable : 1 à 256 octets
"""

# ─── Algorithme RC4 ───────────────────────────────────────────────────────────

class RC4:
    """
    RC4 stream cipher.
    La même instance chiffre ET déchiffre (XOR symétrique).
    """

    def __init__(self, key: bytes):
        assert 1 <= len(key) <= 256, "Clé RC4 : 1 à 256 octets"
        self.key = key

    def _ksa(self) -> list:
        """Key Scheduling Algorithm (KSA) — initialise la S-Box."""
        S = list(range(256))
        j = 0
        key = self.key
        klen = len(key)
        for i in range(256):
            j = (j + S[i] + key[i % klen]) % 256
            S[i], S[j] = S[j], S[i]
        return S

    def _prga(self, S: list, length: int):
        """Pseudo-Random Generation Algorithm — produit le keystream."""
        i = j = 0
        keystream = bytearray()
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            keystream.append(S[(S[i] + S[j]) % 256])
        return bytes(keystream)

    def encrypt(self, plaintext: bytes) -> bytes:
        S = self._ksa()
        keystream = self._prga(S, len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, keystream))

    def decrypt(self, ciphertext: bytes) -> bytes:
        # RC4 est symétrique : déchiffrer = chiffrer
        return self.encrypt(ciphertext)

    def keystream(self, length: int) -> bytes:
        """Retourne `length` octets du keystream."""
        S = self._ksa()
        return self._prga(S, length)


# ─── Tests ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("TEST RC4 - Vecteurs RFC 6229")
    print("=" * 60)

    # Vecteur 1 : clé = "Key", plaintext = "Plaintext"
    key1 = b"Key"
    pt1  = b"Plaintext"
    rc4  = RC4(key1)
    ct1  = rc4.encrypt(pt1)
    print(f"Clé        : {key1}")
    print(f"Plaintext  : {pt1}")
    print(f"Ciphertext : {ct1.hex().upper()}")
    # Vérification connue
    expected1 = bytes.fromhex("BBF316E8D940AF0AD3")
    print(f"Attendu    : {expected1.hex().upper()}")
    print(f"✓ RFC OK   : {ct1 == expected1}")

    # Déchiffrement
    pt1_dec = RC4(key1).decrypt(ct1)
    print(f"Déchiffré  : {pt1_dec}")
    print(f"✓ Inverse  : {pt1_dec == pt1}")

    print()
    print("=" * 60)
    print("TEST RC4 - Vecteur 2 : clé = 'Wiki', plaintext = 'pedia'")
    print("=" * 60)

    key2 = b"Wiki"
    pt2  = b"pedia"
    ct2  = RC4(key2).encrypt(pt2)
    expected2 = bytes.fromhex("1021BF0420")
    print(f"Clé        : {key2}")
    print(f"Plaintext  : {pt2}")
    print(f"Ciphertext : {ct2.hex().upper()}")
    print(f"Attendu    : {expected2.hex().upper()}")
    print(f"✓ OK       : {ct2 == expected2}")

    print()
    print("=" * 60)
    print("TEST RC4 - Vecteur 3 : clé = 'Secret', plaintext = 'Attack at dawn'")
    print("=" * 60)

    key3 = b"Secret"
    pt3  = b"Attack at dawn"
    ct3  = RC4(key3).encrypt(pt3)
    expected3 = bytes.fromhex("45A01F645FC35B383552544B9BF5")
    print(f"Clé        : {key3}")
    print(f"Plaintext  : {pt3}")
    print(f"Ciphertext : {ct3.hex().upper()}")
    print(f"Attendu    : {expected3.hex().upper()}")
    print(f"✓ OK       : {ct3 == expected3}")

    pt3_dec = RC4(key3).decrypt(ct3)
    print(f"Déchiffré  : {pt3_dec}")
    print(f"✓ Inverse  : {pt3_dec == pt3}")

    print()
    print("=" * 60)
    print("TEST RC4 - Clé longue 256 octets")
    print("=" * 60)
    key4 = bytes(range(256))
    msg4 = b"Message secret avec cle de 256 octets"
    r4   = RC4(key4)
    ct4  = r4.encrypt(msg4)
    assert RC4(key4).decrypt(ct4) == msg4
    print(f"✓ Clé 256 octets OK : {msg4}")

    print()
    print("=" * 60)
    print("KEYSTREAM RC4 (clé='Key', 16 premiers octets)")
    print("=" * 60)
    ks = RC4(b"Key").keystream(16)
    print(f"Keystream  : {ks.hex().upper()}")
