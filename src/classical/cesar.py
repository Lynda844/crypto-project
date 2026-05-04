
def encrypt(message: str, key: int) -> str:
    if not isinstance(key, int):
        raise TypeError("La clé doit être un entier")
    
    key = key % 26
    
    result = []
    
    for char in message:
        if char.isalpha():
            if char.isupper():
                pos = ord(char) - ord('A')
                new_pos = (pos + key) % 26
                encrypted_char = chr(new_pos + ord('A'))
                result.append(encrypted_char)
            else:
                pos = ord(char) - ord('a')
                new_pos = (pos + key) % 26
                encrypted_char = chr(new_pos + ord('a'))
                result.append(encrypted_char)
        else:
            result.append(char)
    
    return ''.join(result)


def decrypt(encrypted_message: str, key: int) -> str:
    if not isinstance(key, int):
        raise TypeError("La clé doit être un entier")
    
    key = key % 26
    
    result = []
    
    for char in encrypted_message:
        if char.isalpha():
            if char.isupper():
                pos = ord(char) - ord('A')
                original_pos = (pos - key) % 26
                decrypted_char = chr(original_pos + ord('A'))
                result.append(decrypted_char)
            else:
                pos = ord(char) - ord('a')
                original_pos = (pos - key) % 26
                decrypted_char = chr(original_pos + ord('a'))
                result.append(decrypted_char)
        else:
            result.append(char)
    
    return ''.join(result)


def brute_force_decrypt(encrypted_message: str) -> dict:
    """
    Essaie de déchiffrer un message avec toutes les clés possibles (0-25).
    
    Args:
        encrypted_message (str): Le message chiffré
        
    Returns:
        dict: Dictionnaire avec les clés comme keys et les messages déchiffrés comme values
        
    Exemple:
        >>> results = brute_force_decrypt("ERQMRXU")
        >>> results[3]
        'BONJOUR'
    """
    results = {}
    for key in range(26):
        results[key] = decrypt(encrypted_message, key)
    return results