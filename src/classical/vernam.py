import os
import random


def generate_key(length: int) -> bytes:
    return os.urandom(length)


def generate_key_random(length: int) -> bytes:
    return bytes([random.randint(0, 255) for _ in range(length)])


def encrypt(message: str, key: bytes) -> bytes:
    message_bytes = message.encode('utf-8')
    
    if len(key) < len(message_bytes):
        raise ValueError(f"La clé doit être au moins aussi longue que le message. "
                        f"Message: {len(message_bytes)} octets, Clé: {len(key)} octets")
    
    encrypted = bytes([message_bytes[i] ^ key[i] for i in range(len(message_bytes))])
    
    return encrypted


def decrypt(encrypted_message: bytes, key: bytes) -> str:
    if len(key) < len(encrypted_message):
        raise ValueError(f"La clé doit être au moins aussi longue que le message. "
                        f"Message chiffré: {len(encrypted_message)} octets, Clé: {len(key)} octets")
    
    decrypted = bytes([encrypted_message[i] ^ key[i] for i in range(len(encrypted_message))])
    
    return decrypted.decode('utf-8')


def encrypt_binary(message: str, key: bytes) -> str:
    message_bytes = message.encode('utf-8')
    
    if len(key) < len(message_bytes):
        raise ValueError(f"La clé doit être au moins aussi longue que le message")
    
    binary_result = []
    for i in range(len(message_bytes)):
        xor_result = message_bytes[i] ^ key[i]
        binary_result.append(format(xor_result, '08b'))
    
    return ''.join(binary_result)


def decrypt_binary(encrypted_binary: str, key: bytes) -> str:
    if len(encrypted_binary) % 8 != 0:
        raise ValueError("Le message chiffré en binaire doit avoir une longueur multiple de 8")
    
    num_chars = len(encrypted_binary) // 8
    
    if len(key) < num_chars:
        raise ValueError(f"La clé doit être au moins aussi longue que le message")
    
    decrypted = []
    for i in range(num_chars):
        binary_chunk = encrypted_binary[i*8:(i+1)*8]
        encrypted_byte = int(binary_chunk, 2)
        original_byte = encrypted_byte ^ key[i]
        decrypted.append(chr(original_byte))
    
    return ''.join(decrypted)


def key_to_hex(key: bytes) -> str:
    return key.hex()


def hex_to_key(hex_string: str) -> bytes:
    return bytes.fromhex(hex_string)


def key_to_base64(key: bytes) -> str:
    import base64
    return base64.b64encode(key).decode('utf-8')


def base64_to_key(base64_string: str) -> bytes:
    import base64
    return base64.b64decode(base64_string)


def encrypt_text_with_hex_key(message: str, hex_key: str) -> str:
    key = hex_to_key(hex_key)
    encrypted = encrypt(message, key)
    return encrypted.hex()


def decrypt_text_with_hex_key(hex_encrypted: str, hex_key: str) -> str:
    encrypted = bytes.fromhex(hex_encrypted)
    key = hex_to_key(hex_key)
    return decrypt(encrypted, key)