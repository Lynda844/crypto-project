"""
OTP (One-Time Pad / Masque Jetable) - Implémentation Python pure
Chiffrement parfaitement sûr selon la théorie de Shannon.

Conditions de sécurité :
  1. La clé doit être aussi longue que le message
  2. La clé doit être VRAIMENT aléatoire
  3. La clé ne doit jamais être réutilisée
"""

import os
import secrets

# ─── Classe OTP ───────────────────────────────────────────────────────────────

class OTP:
    """
    One-Time Pad (masque jetable).
    """

    @staticmethod
    def generate_key(length: int) -> bytes:
        """Génère une clé aléatoire cryptographiquement sûre."""
        return secrets.token_bytes(length)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> bytes:
        """
        Chiffre plaintext avec key (XOR bit à bit).
        La clé doit être de longueur >= len(plaintext).
        """
        if len(key) < len(plaintext):
            raise ValueError(
                f"Clé trop courte : {len(key)} < {len(plaintext)} octets. "
                "OTP exige une clé au moins aussi longue que le message."
            )
        return bytes(p ^ k for p, k in zip(plaintext, key))

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes) -> bytes:
        """Déchiffre (identique au chiffrement : XOR est son propre inverse)."""
        return OTP.encrypt(ciphertext, key)

    @staticmethod
    def encrypt_text(plaintext: str, key: bytes, encoding="utf-8") -> bytes:
        """Chiffre une chaîne de caractères."""
        return OTP.encrypt(plaintext.encode(encoding), key)

    @staticmethod
    def decrypt_text(ciphertext: bytes, key: bytes, encoding="utf-8") -> str:
        """Déchiffre vers une chaîne de caractères."""
        return OTP.decrypt(ciphertext, key).decode(encoding)


# ─── Démonstration de la faille de la réutilisation de clé ──────────────────

def demo_key_reuse_attack():
    """
    Illustre pourquoi on ne doit JAMAIS réutiliser une clé OTP.
    Si C1 = M1 XOR K et C2 = M2 XOR K,
    alors C1 XOR C2 = M1 XOR M2  (la clé disparaît !)
    """
    key = OTP.generate_key(50)
    m1  = b"ATTACK AT DAWN ON THE NORTH GATE"
    m2  = b"RETREAT TO BASE CAMP IMMEDIATELY"

    # Réutilisation de la même clé — ERREUR de sécurité !
    c1 = OTP.encrypt(m1, key)
    c2 = OTP.encrypt(m2, key)

    # L'attaquant n'a que c1 et c2, pas la clé
    xor_ct = bytes(a ^ b for a, b in zip(c1, c2))
    xor_pt = bytes(a ^ b for a, b in zip(m1, m2))

    return xor_ct, xor_pt, xor_ct == xor_pt


# ─── Tests ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("TEST OTP - Exemple de base")
    print("=" * 60)

    msg = b"Hello OTP World!"
    key = OTP.generate_key(len(msg))

    ct  = OTP.encrypt(msg, key)
    pt  = OTP.decrypt(ct, key)

    print(f"Message    : {msg}")
    print(f"Clé (hex)  : {key.hex()}")
    print(f"Chiffré    : {ct.hex()}")
    print(f"Déchiffré  : {pt}")
    print(f"✓ Résultat : {pt == msg}")

    print()
    print("=" * 60)
    print("TEST OTP - Vecteur manuel (XOR connu)")
    print("=" * 60)

    # Vecteur explicite
    pt_vec  = bytes([0x48, 0x65, 0x6C, 0x6C, 0x6F])  # "Hello"
    key_vec = bytes([0x01, 0x02, 0x03, 0x04, 0x05])
    expected = bytes([0x48^0x01, 0x65^0x02, 0x6C^0x03, 0x6C^0x04, 0x6F^0x05])

    ct_vec = OTP.encrypt(pt_vec, key_vec)
    print(f"Plaintext  : {pt_vec.hex()}  ({pt_vec})")
    print(f"Clé        : {key_vec.hex()}")
    print(f"Attendu    : {expected.hex()}")
    print(f"Obtenu     : {ct_vec.hex()}")
    print(f"✓ XOR OK   : {ct_vec == expected}")
    print(f"✓ Déchiffré: {OTP.decrypt(ct_vec, key_vec)}")

    print()
    print("=" * 60)
    print("TEST OTP - Texte Unicode")
    print("=" * 60)

    msg_txt = "Cryptographie : الخوارزمية"
    key_txt = OTP.generate_key(len(msg_txt.encode("utf-8")))
    ct_txt  = OTP.encrypt_text(msg_txt, key_txt)
    pt_txt  = OTP.decrypt_text(ct_txt, key_txt)
    print(f"Message    : {msg_txt}")
    print(f"Chiffré    : {ct_txt.hex()}")
    print(f"Déchiffré  : {pt_txt}")
    print(f"✓ Unicode  : {pt_txt == msg_txt}")

    print()
    print("=" * 60)
    print("TEST OTP - Erreur si clé trop courte")
    print("=" * 60)

    try:
        OTP.encrypt(b"Message long", b"court")
        print("✗ Erreur non levée !")
    except ValueError as e:
        print(f"✓ Exception capturée : {e}")

    print()
    print("=" * 60)
    print("DEMO - Attaque par réutilisation de clé")
    print("=" * 60)

    xor_ct, xor_pt, match = demo_key_reuse_attack()
    print("Si un attaquant intercepte C1 et C2 chiffrés avec la MÊME clé :")
    print(f"  C1 XOR C2 (ciphertext) : {xor_ct.hex()}")
    print(f"  M1 XOR M2 (plaintext)  : {xor_pt.hex()}")
    print(f"  Égaux ?                : {match}")
    print("→ La clé disparaît ! L'attaquant obtient M1 XOR M2.")
    print("→ Avec des hypothèses sur le langage, les deux messages peuvent")
    print("  être retrouvés sans jamais avoir eu la clé.")
    print()
    print("⚠  RÈGLE ABSOLUE : une clé OTP ne s'utilise qu'UNE SEULE FOIS.")
