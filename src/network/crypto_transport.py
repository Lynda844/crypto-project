import base64
import json
import socket
import struct
from pathlib import Path
import sys


# Permet d'executer les scripts directement depuis src/network.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.symmetric.aes import AES
from src.symmetric.des import DES
from src.symmetric.rc4 import RC4


SUPPORTED_ALGORITHMS = {"aes", "des", "rc4"}


def _normalize_algorithm(algorithm: str) -> str:
    algo = algorithm.lower().strip()
    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algorithme non supporte: {algorithm}")
    return algo


def _normalize_key(algorithm: str, key: str) -> bytes:
    key_bytes = key.encode("utf-8")

    if algorithm == "aes":
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError("AES exige une cle de 16, 24 ou 32 octets")
    elif algorithm == "des":
        if len(key_bytes) != 8:
            raise ValueError("DES exige une cle de 8 octets")
    elif algorithm == "rc4":
        if not (1 <= len(key_bytes) <= 256):
            raise ValueError("RC4 exige une cle de 1 a 256 octets")

    return key_bytes


def encrypt_payload(algorithm: str, key: str, plaintext: str) -> bytes:
    algo = _normalize_algorithm(algorithm)
    key_bytes = _normalize_key(algo, key)
    plain_bytes = plaintext.encode("utf-8")

    if algo == "aes":
        ciphertext = AES(key_bytes).encrypt(plain_bytes)
    elif algo == "des":
        ciphertext = DES(key_bytes).encrypt(plain_bytes)
    else:
        ciphertext = RC4(key_bytes).encrypt(plain_bytes)

    packet = {
        "algorithm": algo,
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "encoding": "utf-8",
    }
    return json.dumps(packet, ensure_ascii=True).encode("utf-8")


def decrypt_payload(expected_algorithm: str, key: str, packet_bytes: bytes) -> str:
    algo = _normalize_algorithm(expected_algorithm)
    key_bytes = _normalize_key(algo, key)

    packet = json.loads(packet_bytes.decode("utf-8"))
    packet_algo = _normalize_algorithm(packet["algorithm"])

    if packet_algo != algo:
        raise ValueError(
            f"Algorithme recu ({packet_algo}) different de celui configure ({algo})"
        )

    ciphertext = base64.b64decode(packet["ciphertext_b64"])

    if algo == "aes":
        plain_bytes = AES(key_bytes).decrypt(ciphertext)
    elif algo == "des":
        plain_bytes = DES(key_bytes).decrypt(ciphertext)
    else:
        plain_bytes = RC4(key_bytes).decrypt(ciphertext)

    return plain_bytes.decode(packet.get("encoding", "utf-8"))


def send_framed(sock: socket.socket, payload: bytes) -> None:
    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def recv_framed(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    if not header:
        raise ConnectionError("Connexion fermee avant lecture de l'entete")

    length = struct.unpack("!I", header)[0]
    if length <= 0:
        raise ValueError("Longueur de paquet invalide")

    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, total: int) -> bytes:
    chunks = []
    received = 0

    while received < total:
        chunk = sock.recv(total - received)
        if not chunk:
            raise ConnectionError("Connexion fermee pendant la reception")
        chunks.append(chunk)
        received += len(chunk)

    return b"".join(chunks)
