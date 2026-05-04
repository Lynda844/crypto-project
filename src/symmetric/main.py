from .symmetric import aes, des, rc4, otp


def print_menu():
    print("\n" + "="*60)
    print("ALGORITHMES SYMÉTRIQUES DE CHIFFREMENT")
    print("="*60)
    print("\nChoisissez un algorithme :")
    print("  1. AES  (Advanced Encryption Standard)")
    print("  2. DES  (Data Encryption Standard)")
    print("  3. RC4  (Rivest Cipher 4 - stream cipher)")
    print("  4. OTP  (One-Time Pad / Masque Jetable)")
    print("  0. Quitter")
    print("-"*60)


# ─────────────────────────────────────────────────────────────────────────────
# AES
# ─────────────────────────────────────────────────────────────────────────────

def test_aes():
    print("\nCHIFFREMENT AES")
    print("-"*60)
    print("  Tailles de clé supportées :")
    print("    AES-128 → clé de 16 octets")
    print("    AES-192 → clé de 24 octets")
    print("    AES-256 → clé de 32 octets")
    print("-"*60)

    try:
        operation = input("Voulez-vous (c)rypter ou (d)écrypter ? [c/d] : ").lower().strip()

        if operation not in ['c', 'd']:
            print("Choix invalide !")
            return

        if operation == 'c':
            message = input("Entrez le message en clair : ")
            if not message:
                print("Le message ne peut pas être vide !")
                return
        else:
            hex_msg = input("Entrez le message chiffré (hexadécimal) : ").strip()
            try:
                cipher_bytes = bytes.fromhex(hex_msg)
            except ValueError:
                print("Format hexadécimal invalide !")
                return

        key_input = input("Entrez la clé (texte ou hex avec préfixe 0x) : ").strip()

        if key_input.startswith("0x") or key_input.startswith("0X"):
            try:
                key = bytes.fromhex(key_input[2:])
            except ValueError:
                print("Format hexadécimal invalide pour la clé !")
                return
        else:
            key = key_input.encode('utf-8')

        if len(key) not in (16, 24, 32):
            print(f"Longueur de clé invalide : {len(key)} octet(s).")
            print("AES requiert exactement 16, 24 ou 32 octets.")
            return

        cipher = aes.AES(key)

        if operation == 'c':
            result = cipher.encrypt(message.encode('utf-8'))
            print(f"\nMessage chiffré (hex) : {result.hex()}")
        else:
            result = cipher.decrypt(cipher_bytes)
            print(f"\nMessage déchiffré : {result.decode('utf-8')}")

    except ValueError as e:
        print(f"Erreur : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")


# ─────────────────────────────────────────────────────────────────────────────
# DES
# ─────────────────────────────────────────────────────────────────────────────

def test_des():
    print("\nCHIFFREMENT DES")
    print("-"*60)
    print("  Clé : exactement 8 octets (64 bits, 56 bits effectifs)")
    print("-"*60)

    try:
        operation = input("Voulez-vous (c)rypter ou (d)écrypter ? [c/d] : ").lower().strip()

        if operation not in ['c', 'd']:
            print("Choix invalide !")
            return

        if operation == 'c':
            message = input("Entrez le message en clair : ")
            if not message:
                print("Le message ne peut pas être vide !")
                return
        else:
            hex_msg = input("Entrez le message chiffré (hexadécimal) : ").strip()
            try:
                cipher_bytes = bytes.fromhex(hex_msg)
            except ValueError:
                print("Format hexadécimal invalide !")
                return

        key_input = input("Entrez la clé (texte 8 caractères ou hex avec préfixe 0x) : ").strip()

        if key_input.startswith("0x") or key_input.startswith("0X"):
            try:
                key = bytes.fromhex(key_input[2:])
            except ValueError:
                print("Format hexadécimal invalide pour la clé !")
                return
        else:
            key = key_input.encode('utf-8')

        if len(key) != 8:
            print(f"Longueur de clé invalide : {len(key)} octet(s). DES requiert exactement 8 octets.")
            return

        cipher = des.DES(key)

        if operation == 'c':
            result = cipher.encrypt(message.encode('utf-8'))
            print(f"\nMessage chiffré (hex) : {result.hex()}")
        else:
            result = cipher.decrypt(cipher_bytes)
            print(f"\nMessage déchiffré : {result.decode('utf-8')}")

    except ValueError as e:
        print(f"Erreur : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")


# ─────────────────────────────────────────────────────────────────────────────
# RC4
# ─────────────────────────────────────────────────────────────────────────────

def test_rc4():
    print("\nCHIFFREMENT RC4")
    print("-"*60)
    print("  Clé : 1 à 256 octets (stream cipher, chiffre = déchiffre)")
    print("-"*60)

    try:
        operation = input("Voulez-vous (c)rypter ou (d)écrypter ? [c/d] : ").lower().strip()

        if operation not in ['c', 'd']:
            print("Choix invalide !")
            return

        if operation == 'c':
            message = input("Entrez le message en clair : ")
            if not message:
                print("Le message ne peut pas être vide !")
                return
            data = message.encode('utf-8')
        else:
            hex_msg = input("Entrez le message chiffré (hexadécimal) : ").strip()
            try:
                data = bytes.fromhex(hex_msg)
            except ValueError:
                print("Format hexadécimal invalide !")
                return

        key_input = input("Entrez la clé (texte ou hex avec préfixe 0x) : ").strip()

        if key_input.startswith("0x") or key_input.startswith("0X"):
            try:
                key = bytes.fromhex(key_input[2:])
            except ValueError:
                print("Format hexadécimal invalide pour la clé !")
                return
        else:
            key = key_input.encode('utf-8')

        if not (1 <= len(key) <= 256):
            print(f"Longueur de clé invalide : {len(key)} octet(s). RC4 requiert entre 1 et 256 octets.")
            return

        cipher = rc4.RC4(key)

        if operation == 'c':
            result = cipher.encrypt(data)
            print(f"\nMessage chiffré (hex) : {result.hex()}")
        else:
            result = cipher.decrypt(data)
            try:
                print(f"\nMessage déchiffré : {result.decode('utf-8')}")
            except UnicodeDecodeError:
                print(f"\nMessage déchiffré (hex) : {result.hex()}")

    except ValueError as e:
        print(f"Erreur : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")


# ─────────────────────────────────────────────────────────────────────────────
# OTP
# ─────────────────────────────────────────────────────────────────────────────

def test_otp():
    print("\nCHIFFREMENT OTP (One-Time Pad / Masque Jetable)")
    print("-"*60)
    print("  Règles absolues :")
    print("    - La clé doit être aussi longue que le message")
    print("    - La clé doit être aléatoire et secrète")
    print("    - La clé ne doit JAMAIS être réutilisée")
    print("-"*60)

    try:
        operation = input("Voulez-vous (c)rypter ou (d)écrypter ? [c/d] : ").lower().strip()

        if operation not in ['c', 'd']:
            print("Choix invalide !")
            return

        if operation == 'c':
            message = input("Entrez le message en clair : ")
            if not message:
                print("Le message ne peut pas être vide !")
                return

            message_bytes = message.encode('utf-8')

            key_choice = input("Générer une clé aléatoire automatiquement ? [o/n] : ").lower().strip()

            if key_choice == 'o':
                key = otp.OTP.generate_key(len(message_bytes))
                print(f"\nClé générée (hex) : {key.hex()}")
                print("⚠  Conservez cette clé ! Elle est nécessaire pour déchiffrer.")
            else:
                key_input = input("Entrez la clé (hexadécimal) : ").strip()
                try:
                    key = bytes.fromhex(key_input)
                except ValueError:
                    print("Format hexadécimal invalide !")
                    return

            result = otp.OTP.encrypt(message_bytes, key)
            print(f"\nMessage chiffré (hex) : {result.hex()}")

        else:
            hex_msg = input("Entrez le message chiffré (hexadécimal) : ").strip()
            try:
                cipher_bytes = bytes.fromhex(hex_msg)
            except ValueError:
                print("Format hexadécimal invalide !")
                return

            key_input = input("Entrez la clé (hexadécimal) : ").strip()
            try:
                key = bytes.fromhex(key_input)
            except ValueError:
                print("Format hexadécimal invalide pour la clé !")
                return

            result = otp.OTP.decrypt(cipher_bytes, key)
            try:
                print(f"\nMessage déchiffré : {result.decode('utf-8')}")
            except UnicodeDecodeError:
                print(f"\nMessage déchiffré (hex) : {result.hex()}")

    except ValueError as e:
        print(f"Erreur : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    while True:
        print_menu()
        choice = input("Votre choix : ").strip()

        if choice == '1':
            test_aes()
        elif choice == '2':
            test_des()
        elif choice == '3':
            test_rc4()
        elif choice == '4':
            test_otp()
        elif choice == '0':
            print("\nAu revoir ! Merci d'avoir utilisé le testeur d'algorithmes symétriques.")
            break
        else:
            print("Choix invalide ! Veuillez entrer un nombre entre 0 et 4.")

        input("\nAppuyez sur Entrée pour continuer...")


if __name__ == "__main__":
    main()
