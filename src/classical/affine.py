import math
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def is_valid_key_a(a: int) -> bool:
    return gcd(a, 26) == 1


def mod_inverse(a: int, m: int) -> int:
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    raise ValueError(f"L'inverse multiplicatif de {a} modulo {m} n'existe pas")


def encrypt(message: str, a: int, b: int) -> str:
    if not is_valid_key_a(a):
        raise ValueError(f"a = {a} n'est pas premier avec 26. Choisissez a dans: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25")
    
    result = []
    
    for char in message:
        if char.isalpha():
            if char.isupper():
                P = ord(char) - ord('A')
                C = (a * P + b) % 26
                encrypted_char = chr(C + ord('A'))
                result.append(encrypted_char)
            else:
                P = ord(char) - ord('a')
                C = (a * P + b) % 26
                encrypted_char = chr(C + ord('a'))
                result.append(encrypted_char)
        else:
            result.append(char)
    
    return ''.join(result)


def decrypt(encrypted_message: str, a: int, b: int) -> str:
    if not is_valid_key_a(a):
        raise ValueError(f"a = {a} n'est pas premier avec 26. Choisissez a dans: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25")
    
    a_inverse = mod_inverse(a, 26)
    result = []
    
    for char in encrypted_message:
        if char.isalpha():
            if char.isupper():
                C = ord(char) - ord('A')
                P = (a_inverse * (C - b)) % 26
                decrypted_char = chr(P + ord('A'))
                result.append(decrypted_char)
            else:
                C = ord(char) - ord('a')
                P = (a_inverse * (C - b)) % 26
                decrypted_char = chr(P + ord('a'))
                result.append(decrypted_char)
        else:
            result.append(char)
    
    return ''.join(result)


def get_valid_a_values():
    return [i for i in range(1, 26) if is_valid_key_a(i)]