import argparse
import socket

from crypto_transport import encrypt_payload, send_framed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sender TCP: chiffre un message puis l'envoie au receiver"
    )
    parser.add_argument("--host", default="127.0.0.1", help="IP du receiver")
    parser.add_argument("--port", type=int, default=5000, help="Port du receiver")
    parser.add_argument(
        "--algorithm",
        choices=["aes", "des", "rc4"],
        default="aes",
        help="Algorithme de chiffrement",
    )
    parser.add_argument("--key", required=True, help="Cle partagee (texte)")
    parser.add_argument("--message", help="Message a envoyer")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    message = args.message if args.message is not None else input("Message a envoyer: ")

    payload = encrypt_payload(args.algorithm, args.key, message)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((args.host, args.port))
        send_framed(client, payload)

    print("Message chiffre et envoye avec succes.")


if __name__ == "__main__":
    main()
