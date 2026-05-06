try:
    from . import cesar, affine, playfair, substitution, vernam, hill
except ImportError:
    import cesar
    import affine
    import playfair
    import substitution
    import vernam
    import hill

def print_menu():
    print("\n" + "="*60)
    print("ALGORITHMES CLASSIQUES DE CHIFFREMENT")
    print("="*60)
    print("\nChoisissez un algorithme :")
    print("  1. César")
    print("  2. Affine")
    print("  3. Playfair")
    print("  4. Substitution")
    print("  5. Vernam (One-Time Pad)")
    print("  6. Hill")
    print("  0. Quitter")
    print("-"*60)


def test_cesar():
    print("\nCHIFFREMENT CÉSAR")
    print("-"*60)

    try:
        operation = input("Voulez-vous (c)rypter ou (d)écrypter ? [c/d] : ").lower().strip()

        if operation not in ['c', 'd']:
            print("Choix invalide !")
            return

        message = input("Entrez le message : ")

        if not message:
            print("Le message ne peut pas être vide !")
            return

        key = int(input("Entrez la clé (nombre entier) : "))

        if operation == 'c':
            result = cesar.encrypt(message, key)
            print(f"\nMessage chiffré : {result}")
        else:
            result = cesar.decrypt(message, key)
            print(f"\nMessage déchiffré : {result}")

    except ValueError as e:
        print(f"Erreur : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")


def test_affine():
    print("\nCHIFFREMENT AFFINE")
    print("-"*60)
    print("  Format : C ≡ (a × P + b) mod 26")
    print("  a doit être premier avec 26 : [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]")
    print("-"*60)

    try:
        operation = input("Voulez-vous (c)rypter ou (d)écrypter ? [c/d] : ").lower().strip()

        if operation not in ['c', 'd']:
            print("Choix invalide !")
            return

        message = input("Entrez le message : ")

        if not message:
            print("Le message ne peut pas être vide !")
            return

        a = int(input("Entrez le paramètre 'a' : "))
        b = int(input("Entrez le paramètre 'b' : "))

        if operation == 'c':
            result = affine.encrypt(message, a, b)
            print(f"\nMessage chiffré : {result}")
        else:
            result = affine.decrypt(message, a, b)
            print(f"\nMessage déchiffré : {result}")

    except ValueError as e:
        print(f"Erreur : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")


def test_playfair():
    print("\nCHIFFREMENT PLAYFAIR")
    print("-"*60)

    try:
        operation = input("Voulez-vous (c)rypter ou (d)écrypter ? [c/d] : ").lower().strip()

        if operation not in ['c', 'd']:
            print("Choix invalide !")
            return

        message = input("Entrez le message : ")

        if not message:
            print("Le message ne peut pas être vide !")
            return

        keyword = input("Entrez le mot-clé : ")

        if not keyword:
            print("Le mot-clé ne peut pas être vide !")
            return

        if operation == 'c':
            result = playfair.encrypt(message, keyword)
            print(f"\nMessage chiffré : {result}")
        else:
            result = playfair.decrypt(message, keyword)
            print(f"\nMessage déchiffré : {result}")

    except ValueError as e:
        print(f"Erreur : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")


def test_substitution():
    print("\nCHIFFREMENT DE SUBSTITUTION")
    print("-"*60)

    try:
        operation = input("Voulez-vous (c)rypter ou (d)écrypter ? [c/d] : ").lower().strip()

        if operation not in ['c', 'd']:
            print("Choix invalide !")
            return

        message = input("Entrez le message : ")

        if not message:
            print("Le message ne peut pas être vide !")
            return

        key = input("Entrez la clé de substitution (26 caractères) : ")

        if len(key) != 26:
            print(f"La clé doit contenir exactement 26 caractères (vous en avez entré {len(key)}) !")
            return

        if operation == 'c':
            result = substitution.encrypt(message, key)
            print(f"\nMessage chiffré : {result}")
        else:
            result = substitution.decrypt(message, key)
            print(f"\nMessage déchiffré : {result}")

    except ValueError as e:
        print(f"Erreur : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")


def test_vernam():
    print("\nCHIFFREMENT VERNAM (One-Time Pad)")
    print("-"*60)

    try:
        operation = input("Voulez-vous (c)rypter ou (d)écrypter ? [c/d] : ").lower().strip()

        if operation not in ['c', 'd']:
            print("Choix invalide !")
            return

        message = input("Entrez le message : ")

        if not message:
            print("Le message ne peut pas être vide !")
            return

        key_input = input("Entrez la clé (en hexadécimal, ex: 48656c6c6f) : ")

        try:
            key = bytes.fromhex(key_input)
        except ValueError:
            print("Format hexadécimal invalide !")
            return

        if operation == 'c':
            result = vernam.encrypt(message, key)
            result_hex = result.hex()
            print(f"\nMessage chiffré (hex)   : {result_hex}")
            print(f"Message chiffré (bytes) : {result}")
        else:
            try:
                encrypted_bytes = bytes.fromhex(message)
                result = vernam.decrypt(encrypted_bytes, key)
                print(f"\nMessage déchiffré : {result}")
            except ValueError:
                print("Le message chiffré doit être en format hexadécimal !")

    except ValueError as e:
        print(f"Erreur : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")


def test_hill():
    print("\nCHIFFREMENT HILL")
    print("-"*60)
    print("  Clé : matrice 2×2 ou 3×3 inversible modulo 26")
    print("  Exemple 2×2 : [[3,3],[2,5]]  →  entrer : 3 3  puis  2 5")
    print("  Exemple 3×3 : [[6,24,1],[13,16,10],[20,17,15]]")
    print("-"*60)

    try:
        operation = input("Voulez-vous (c)rypter ou (d)écrypter ? [c/d] : ").lower().strip()

        if operation not in ['c', 'd']:
            print("Choix invalide !")
            return

        message = input("Entrez le message : ")

        if not message:
            print("Le message ne peut pas être vide !")
            return

        size = input("Taille de la matrice clé ? [2/3] : ").strip()

        if size not in ['2', '3']:
            print("Taille invalide ! Choisissez 2 ou 3.")
            return

        n = int(size)
        matrix = []

        print(f"Entrez les {n} lignes de la matrice (valeurs séparées par des espaces) :")
        for i in range(n):
            while True:
                try:
                    row_input = input(f"  Ligne {i+1} : ").strip()
                    row = [int(x) for x in row_input.split()]
                    if len(row) != n:
                        print(f"  Entrez exactement {n} valeurs.")
                        continue
                    matrix.append(row)
                    break
                except ValueError:
                    print("  Valeurs entières uniquement.")

        if not hill.is_matrix_invertible(matrix):
            print("Erreur : la matrice n'est pas inversible modulo 26 !")
            print("Vérifiez que gcd(det(matrice), 26) = 1.")
            return

        if operation == 'c':
            result = hill.encrypt(message, matrix)
            print(f"\nMessage chiffré : {result}")
        else:
            result = hill.decrypt(message, matrix)
            print(f"\nMessage déchiffré : {result}")

    except ValueError as e:
        print(f"Erreur : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")


def main():
    while True:
        print_menu()
        choice = input("Votre choix : ").strip()

        if choice == '1':
            test_cesar()
        elif choice == '2':
            test_affine()
        elif choice == '3':
            test_playfair()
        elif choice == '4':
            test_substitution()
        elif choice == '5':
            test_vernam()
        elif choice == '6':
            test_hill()
        elif choice == '0':
            print("\nAu revoir ! Merci d'avoir utilisé le testeur d'algorithmes classiques.")
            break
        else:
            print("Choix invalide ! Veuillez entrer un nombre entre 0 et 6.")

        input("\nAppuyez sur Entrée pour continuer...")


if __name__ == "__main__":
    main()
