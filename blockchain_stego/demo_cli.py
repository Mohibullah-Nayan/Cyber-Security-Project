"""
Interactive CLI Demonstration of Blockchain-Secured Steganography System.
Demonstrates:
1. Carrier image generation.
2. Secret message encryption (AES-256-GCM) + LSB Stego embedding.
3. Cryptographic hash calculation (SHA-256).
4. Proof-of-Work block mining into the blockchain ledger.
5. Extraction and decryption of secret message.
6. Simulating an adversarial 1-pixel tampering attack and detecting it instantly!
"""

import os
import io
import time
from PIL import Image

from core.crypto_utils import calculate_sha256_bytes
from core.steganography import SteganographyEngine
from core.blockchain import Blockchain


def print_banner():
    banner = """
    +===================================================================+
    |  BLOCKCHAIN-SECURED IMAGE STEGANOGRAPHY & TAMPER-DETECTION SYSTEM |
    |               Portfolio & University Research Demo                |
    +===================================================================+
    """
    print(banner)


def main():
    print_banner()

    data_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(data_dir, exist_ok=True)

    # 1. Initialize Blockchain
    print("[1] Initializing Blockchain Ledger with PoW difficulty = 2...")
    blockchain = Blockchain(difficulty=2)
    genesis = blockchain.get_latest_block()
    print(f"    [+] Genesis Block Mined! Hash: {genesis.hash}")

    # 2. Generate Carrier Image
    carrier_path = os.path.join(data_dir, "sample_carrier.png")
    carrier = Image.new("RGB", (300, 300), color=(52, 152, 219))
    carrier.save(carrier_path, format="PNG")
    print(f"\n[2] Created carrier image: {carrier_path} (300x300 RGB)")

    # 3. Embed Secret Message with AES-256-GCM Encryption
    secret_text = "CONFIDENTIAL: Operation CyberShield Launch Coordinates (45.109, -93.265)"
    passphrase = "AlphaOmegaSecureKey!2026"
    print(f"\n[3] Secret Message: '{secret_text}'")
    print(f"    Passphrase: '{passphrase}'")

    print("    Embedding payload into image via LSB + AES-256-GCM...")
    stego_img, stego_bytes = SteganographyEngine.encode(
        carrier,
        message=secret_text,
        passphrase=passphrase,
    )
    stego_path = os.path.join(data_dir, "stego_output.png")
    with open(stego_path, "wb") as f:
        f.write(stego_bytes)
    print(f"    [+] Stego image generated & saved to: {stego_path}")

    # 4. Hash & Mine onto Blockchain
    image_sha256 = calculate_sha256_bytes(stego_bytes)
    print(f"\n[4] Stego Image SHA-256 Fingerprint: {image_sha256}")
    print("    Mining block with Proof-of-Work...")
    t0 = time.time()
    block = blockchain.add_block(
        image_hash=image_sha256,
        image_name="stego_output.png",
        metadata={
            "sender": "Agent-Alpha",
            "recipient": "Station-HQ",
            "encrypted": True,
            "cipher": "AES-256-GCM",
        },
    )
    elapsed = time.time() - t0
    print(f"    [+] Block #{block.index} successfully mined in {elapsed:.3f}s!")
    print(f"        Hash: {block.hash}")
    print(f"        Previous Hash: {block.previous_hash}")
    print(f"        Nonce: {block.nonce}")

    # 5. Extract & Decrypt Secret Message
    print("\n[5] Extracting and decrypting secret from stego image...")
    extracted_message = SteganographyEngine.decode(stego_path, passphrase=passphrase)
    print(f"    [+] Extracted message: '{extracted_message}'")
    assert extracted_message == secret_text

    # 6. Verify Image Integrity on Genuine Image
    print("\n[6] Auditing genuine image against Blockchain Block #1...")
    is_valid, cand_h, rec_h, msg = blockchain.verify_image_integrity(stego_bytes, block.index)
    print(f"    Result: {'PASS [AUTHENTIC]' if is_valid else 'FAIL [TAMPERED]'}")
    print(f"    Message: {msg}")

    # 7. Adversary Attack Simulation (1-Pixel Modification)
    print("\n[7] --- ADVERSARY ATTACK SIMULATION ---")
    print("    Adversary alters just 1 single pixel (e.g. RGB value changed by 1)...")
    tampered_img = stego_img.copy()
    tampered_pixels = tampered_img.load()
    orig_val = tampered_pixels[150, 150]
    tampered_pixels[150, 150] = ((orig_val[0] + 1) % 256, orig_val[1], orig_val[2])

    buf = io.BytesIO()
    tampered_img.save(buf, format="PNG")
    tampered_bytes = buf.getvalue()
    tampered_path = os.path.join(data_dir, "tampered_stego.png")
    with open(tampered_path, "wb") as f:
        f.write(tampered_bytes)

    print(f"    Adversary saves altered file to: {tampered_path}")
    print(f"    Tampered Image SHA-256: {calculate_sha256_bytes(tampered_bytes)}")

    print("\n    Running Blockchain Integrity Verification on tampered image...")
    is_valid, cand_h, rec_h, msg = blockchain.verify_image_integrity(tampered_bytes, block.index)
    print(f"    Result: {'PASS [AUTHENTIC]' if is_valid else 'FAIL [TAMPER DETECTED]'}")
    print(f"    Audit Log: {msg}")

    # 8. Blockchain Ledger Validation
    print("\n[8] Full Blockchain Ledger Cryptographic Audit...")
    chain_valid, chain_err = blockchain.is_chain_valid()
    print(f"    Chain Status: {'VALID & UNCOMPROMISED' if chain_valid else 'COMPROMISED'}")

    ledger_path = os.path.join(data_dir, "blockchain_ledger.json")
    blockchain.save_ledger(ledger_path)
    print(f"    Ledger saved to: {ledger_path}")

    print("\n======================= DEMO COMPLETED SUCCESSFULLY =======================\n")


if __name__ == "__main__":
    main()
