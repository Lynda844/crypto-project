# crypto-project




## 📁 Structure du projet

```
crypto_project/
└── src/
    ├── __init__.py
    ├── classic/
    │   ├── __init__.py
    │   ├── caesar.py
    │   ├── affine.py
    │   ├── playfair.py
    │   ├── substitution.py
    │   ├── vernam.py
    │   ├── hill.py
    │   └── main.py
    └── symmetric/
        ├── __init__.py
        ├── aes.py
        ├── des.py
        ├── rc4.py
        ├── otp.py
        └── main.py
```

---

## 🗂️ Algorithmes implémentés

### Classiques (`src/classic/`)

| Fichier | Algorithme | Type de clé |
|---------|-----------|-------------|
| `caesar.py` | Chiffre de César | Entier (décalage 0–25) |
| `affine.py` | Chiffre Affine | Deux entiers `a`, `b` (a premier avec 26) |
| `playfair.py` | Chiffre Playfair | Mot-clé (matrice 5×5) |
| `substitution.py` | Substitution mono-alphabétique | Permutation de 26 lettres |
| `vernam.py` | Vernam (OTP classique) | Clé hexadécimale |
| `hill.py` | Chiffre de Hill | Matrice 2×2 ou 3×3 inversible mod 26 |

### Symétriques (`src/symmetric/`)

| Fichier | Algorithme | Type de clé |
|---------|-----------|-------------|
| `aes.py` | AES-128 / 192 / 256 | 16, 24 ou 32 octets |
| `des.py` | DES | 8 octets (56 bits effectifs) |
| `rc4.py` | RC4 (stream cipher) | 1 à 256 octets |
| `otp.py` | One-Time Pad | Clé aléatoire = longueur du message |

---

## ⚙️ Prérequis

- Python 3.8 ou supérieur
- Aucune dépendance externe (Python pur)

Vérifier la version Python :
```bash
python --version
```

---

## 🚀 Lancement

### Menu interactif — Algorithmes classiques

```bash
cd crypto_project
python -m src.classic.main
```

```
============================================================
ALGORITHMES CLASSIQUES DE CHIFFREMENT
============================================================

Choisissez un algorithme :
  1. Caesar
  2. Affine
  3. Playfair
  4. Substitution
  5. Vernam (One-Time Pad classique)
  6. Hill
  0. Quitter
```

### Menu interactif — Algorithmes symétriques

```bash
cd crypto_project
python -m src.symmetric.main
```

```
============================================================
ALGORITHMES SYMÉTRIQUES DE CHIFFREMENT
============================================================

Choisissez un algorithme :
  1. AES  (Advanced Encryption Standard)
  2. DES  (Data Encryption Standard)
  3. RC4  (Rivest Cipher 4 - stream cipher)
  4. OTP  (One-Time Pad / Masque Jetable)
  0. Quitter
```

---

## 🧪 Tests intégrés

Chaque fichier contient ses propres vecteurs de test. Pour les lancer :

```bash
# Classiques
python -m src.classic.caesar
python -m src.classic.affine
python -m src.classic.playfair
python -m src.classic.substitution
python -m src.classic.vernam
python -m src.classic.hill

# Symétriques
python -m src.symmetric.aes
python -m src.symmetric.des
python -m src.symmetric.rc4
python -m src.symmetric.otp
```

---

## 📌 Exemples d'utilisation rapide

### Caesar
```python
from src.classic.caesar import encrypt, decrypt

ct = encrypt("BONJOUR", 3)   # → "ERQMRXU"
pt = decrypt("ERQMRXU", 3)   # → "BONJOUR"
```

### Affine
```python
from src.classic.affine import encrypt, decrypt

ct = encrypt("HELLO", 5, 8)   # a=5, b=8
pt = decrypt(ct, 5, 8)
```

### Playfair
```python
from src.classic.playfair import encrypt, decrypt

ct = encrypt("HELLO", "KEYWORD")
pt = decrypt(ct, "KEYWORD")
```

### Substitution
```python
from src.classic.substitution import encrypt, decrypt

key = "QWERTYUIOPASDFGHJKLZXCVBNM"
ct  = encrypt("HELLO", key)
pt  = decrypt(ct, key)
```

### Vernam (classique)
```python
from src.classic.vernam import encrypt, decrypt, generate_key

key = generate_key(10)
ct  = encrypt("BONJOUR", key)
pt  = decrypt(ct, key)
```

### Hill
```python
from src.classic.hill import encrypt, decrypt

matrix = [[3, 3], [2, 5]]
ct = encrypt("HELLO", matrix)
pt = decrypt(ct, matrix)
```

### AES
```python
from src.symmetric.aes import AES

aes = AES(b"cle16octets12345")   # AES-128
ct  = aes.encrypt(b"mon message secret")
pt  = aes.decrypt(ct)
print(pt)  # b"mon message secret"
```

### DES
```python
from src.symmetric.des import DES

des = DES(b"8octets!")
ct  = des.encrypt(b"message!")
pt  = des.decrypt(ct)
print(pt)  # b"message!"
```

### RC4
```python
from src.symmetric.rc4 import RC4

rc4 = RC4(b"masecretkey")
ct  = rc4.encrypt(b"Attack at dawn")
pt  = RC4(b"masecretkey").decrypt(ct)
print(pt)  # b"Attack at dawn"
```

### OTP
```python
from src.symmetric.otp import OTP

msg = b"Hello World"
key = OTP.generate_key(len(msg))   # clé aléatoire
ct  = OTP.encrypt(msg, key)
pt  = OTP.decrypt(ct, key)
print(pt)  # b"Hello World"
```

---

## 🔑 Notes importantes

### AES — Tailles de clé
| Variante | Longueur clé | Rounds |
|----------|-------------|--------|
| AES-128 | 16 octets | 10 |
| AES-192 | 24 octets | 12 |
| AES-256 | 32 octets | 14 |

### DES — Attention sécurité
> DES est considéré **obsolète** depuis 1999 (clé de seulement 56 bits).  
> Il est implémenté ici à des fins **éducatives uniquement**.

### RC4 — Attention sécurité
> RC4 présente des **faiblesses connues** (biais dans le keystream).  
> Déprécié dans TLS depuis 2015. Implémenté ici à des fins **éducatives uniquement**.

### OTP — Règles absolues
> 1. La clé doit être **aussi longue** que le message  
> 2. La clé doit être **vraiment aléatoire**  
> 3. La clé ne doit **jamais être réutilisée**  
> Si une clé est réutilisée : `C1 XOR C2 = M1 XOR M2` → les messages sont récupérables !

---

## ✅ Vecteurs de test utilisés

| Algorithme | Source du vecteur |
|-----------|------------------|
| AES | NIST FIPS-197 Appendix B |
| DES | FIPS PUB 81 |
| RC4 | RFC 6229 (Key/Plaintext, Wiki/pedia, Secret/Attack at dawn) |
| OTP | Vecteurs XOR manuels vérifiés |

