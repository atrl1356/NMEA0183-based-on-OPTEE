import socket
import argparse

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RECORD_VERSION = 0x01
NONCE_SIZE = 12
TAG_SIZE = 16
MASTER_KEY_SIZE = 32

HKDF_SALT = b"STATION-HKDF-SALT"
HKDF_INFO_PREFIX = b"STATION-LOG-V1"

def dump_hex(label: str, data: bytes):
    print(f"{label}")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        print(" ".join(f"{b:02x}" for b in chunk))

def derive_key(master_key: bytes, seq: int) -> bytes:
    seq_be = seq.to_bytes(8, "big")
    info = HKDF_INFO_PREFIX + seq_be
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=info,
    )
    return hkdf.derive(master_key)

def parse_record(data: bytes):
    if len(data) < 1 + 8 + NONCE_SIZE + 4 + TAG_SIZE:
        raise ValueError("record too short")

    version = data[0]
    if version != RECORD_VERSION:
        raise ValueError(f"unsupported version: {version}")

    seq = int.from_bytes(data[1:9], "big")
    nonce = data[9:21]
    ct_len = int.from_bytes(data[21:25], "big")

    if len(data) != 1 + 8 + NONCE_SIZE + 4 + ct_len + TAG_SIZE:
        raise ValueError("record length mismatch")

    ciphertext = data[25:25 + ct_len]
    tag = data[25 + ct_len:25 + ct_len + TAG_SIZE]
    return version, seq, nonce, ct_len, ciphertext, tag

def decrypt_record(master_key: bytes, data: bytes) -> bytes:
    version, seq, nonce, ct_len, ciphertext, tag = parse_record(data)

    derived_key = derive_key(master_key, seq)
    aad = (
        bytes([version]) +
        seq.to_bytes(8, "big") +
        nonce +
        ct_len.to_bytes(4, "big")
    )

    aesgcm = AESGCM(derived_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, aad)
    return plaintext, version, seq, nonce, ct_len, ciphertext, tag

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-ip", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--master-key-hex", required=True,
                        help="32-byte master key in hex")
    args = parser.parse_args()

    master_key = bytes.fromhex(args.master_key_hex)
    if len(master_key) != MASTER_KEY_SIZE:
        raise ValueError("master key must be 32 bytes (64 hex chars)")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen_ip, args.listen_port))

    print(f"[Receiver] listening on {args.listen_ip}:{args.listen_port}")

    while True:
        data, addr = sock.recvfrom(65535)
        try:
            print(f"[Receiver] packet from {addr}")
            dump_hex("Full sealed record:", data)

            plaintext, version, seq, nonce, ct_len, ciphertext, tag = decrypt_record(master_key, data)

            print(f"[Receiver] version = {version}")
            print(f"[Receiver] seq = {seq}")
            dump_hex("[Receiver] Nonce:", nonce)
            print(f"[Receiver] ct_len = {ct_len}")
            dump_hex("[Receiver] Ciphertext:", ciphertext)
            dump_hex("[Receiver] Tag:", tag)

            print(f"[Receiver] plaintext:\n{plaintext.decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"[Receiver] decrypt failed from {addr}: {e}")

if __name__ == "__main__":
    main()
