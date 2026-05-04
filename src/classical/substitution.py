import random
import string


def generate_key():
    alphabet = list(string.ascii_uppercase)
    random.shuffle(alphabet)
    return ''.join(alphabet)


def encrypt(message: str, key: str) -> str:
    if len(key) != 26:
        raise ValueError("La clé doit contenir exactement 26 caractères")
    
    if len(set(key.upper())) != 26:
        raise ValueError("La clé doit contenir exactement 26 caractères uniques (une permutation de l'alphabet)")
    
    alphabet = string.ascii_uppercase
    result = []
    
    for char in message:
        if char.upper() in alphabet:
            index = alphabet.index(char.upper())
            encrypted_char = key[index]
            
            if char.islower():
                encrypted_char = encrypted_char.lower()
            
            result.append(encrypted_char)
        else:
            result.append(char)
    
    return ''.join(result)


def decrypt(encrypted_message: str, key: str) -> str:
    if len(key) != 26:
        raise ValueError("La clé doit contenir exactement 26 caractères")
    
    if len(set(key.upper())) != 26:
        raise ValueError("La clé doit contenir exactement 26 caractères uniques (une permutation de l'alphabet)")
    
    alphabet = string.ascii_uppercase
    inverse_key = {}
    
    for index, encrypted_char in enumerate(key):
        inverse_key[encrypted_char.upper()] = alphabet[index]
    
    result = []
    
    for char in encrypted_message:
        if char.upper() in inverse_key:
            original_char = inverse_key[char.upper()]
            
            if char.islower():
                original_char = original_char.lower()
            
            result.append(original_char)
        else:
            result.append(char)
    
    return ''.join(result)


def brute_force_decrypt(encrypted_message: str) -> str:
    frequency_analysis = {
        'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
        'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25
    }
    
    return f"Analyse fréquentielle nécessaire avec données: {frequency_analysis}"