import argparse
import socket

from crypto_transport import decrypt_payload, recv_framed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Receiver TCP: recoit un message chiffre puis le dechiffre"
    )
    parser.add_argument("--host", default="0.0.0.0", help="IP locale d'ecoute")
    parser.add_argument("--port", type=int, default=5000, help="Port d'ecoute")
    parser.add_argument(
        "--algorithm",
        choices=["aes", "des", "rc4"],
        default="aes",
        help="Algorithme attendu",
    )
    parser.add_argument("--key", required=True, help="Cle partagee (texte)")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Arrete le serveur apres un message",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen(5)

        print(f"Receiver en ecoute sur {args.host}:{args.port} ({args.algorithm.upper()})")

        while True:
            conn, addr = server.accept()
            with conn:
                print(f"Connexion entrante depuis {addr[0]}:{addr[1]}")
                try:
                    packet = recv_framed(conn)
                    message = decrypt_payload(args.algorithm, args.key, packet)
                    print(f"Message dechiffre: {message}")
                except Exception as exc:
                    print(f"Erreur pendant le traitement: {exc}")

            if args.once:
                break


if __name__ == "__main__":
    main()
