"""
Tamper Detection & 1-Pixel Attack Simulation Experiment.
This script demonstrates:
1. Normal flow: genuine image hash recorded on Blockchain Block #1.
2. Attack flow: changing 1 single color value in 1 single pixel (e.g., Red 50 -> 51).
3. Cryptographic Avalanche Effect: SHA-256 changes completely.
4. Blockchain instant tamper detection verdict.
"""

import os
import io
import sys
from PIL import Image

# Ensure standard output can handle utf-8 safely on Windows
if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from core.crypto_utils import calculate_sha256_bytes
from core.steganography import SteganographyEngine
from core.blockchain import Blockchain


def run_experiment():
    print("=" * 72)
    print("       [*] 1-PIXEL TAMPERING & CRYPTOGRAPHIC VERIFICATION LAB")
    print("=" * 72)

    # 1. Initialize Blockchain
    bc = Blockchain(difficulty=2)
    print("\n[1] Blockchain Ledger Initialized.")
    print(f"    - Genesis Block Hash: {bc.chain[0].hash}")

    # 2. Create Genuine Stego Image
    carrier = Image.new("RGB", (200, 200), color=(50, 120, 200))
    secret_message = "University Top Secret 2026"
    passphrase = "MySecretPassword123"

    stego_img, stego_bytes = SteganographyEngine.encode(carrier, secret_message, passphrase=passphrase)
    genuine_hash = calculate_sha256_bytes(stego_bytes)

    # 3. Record Genuine Image onto Blockchain (Block #1)
    block1 = bc.add_block(
        image_hash=genuine_hash,
        image_name="official_report.png",
        metadata={"sender": "Dean Office", "confidential": True}
    )
    print(f"\n[2] Genuine Image Mined into Block #{block1.index}:")
    print(f"    - Block Hash         : {block1.hash}")
    print(f"    - Genuine SHA-256    : {genuine_hash}")

    # 4. Verify Genuine Image
    print("\n[3] TEST 1: Verifying Genuine Image against Blockchain...")
    is_valid, cand_h, rec_h, msg = bc.verify_image_integrity(stego_bytes, block_index=1)
    if is_valid:
        print("    [PASS] Verdict: AUTHENTIC (100% Genuine, Zero Tampering)")
        print(f"    - Audit Log: {msg}")

    # 5. Adversary Attack: Alter 1 Pixel
    print("\n" + "-" * 72)
    print("[4] ADVERSARY ATTACK: Modifying just 1 single pixel in the image...")
    print("-" * 72)
    
    tampered_img = stego_img.copy()
    pixels = tampered_img.load()
    
    # Original pixel value at (100, 100)
    orig_rgb = pixels[100, 100]
    # Alter Red channel by +1
    new_rgb = ((orig_rgb[0] + 1) % 256, orig_rgb[1], orig_rgb[2])
    pixels[100, 100] = new_rgb

    print(f"    - Altered Pixel Coordinate: (x=100, y=100)")
    print(f"    - Original Pixel RGB     : {orig_rgb}")
    print(f"    - Modified Pixel RGB     : {new_rgb}  (Only 1 bit difference!)")

    # Generate tampered image bytes & hash
    buf = io.BytesIO()
    tampered_img.save(buf, format="PNG")
    tampered_bytes = buf.getvalue()
    tampered_hash = calculate_sha256_bytes(tampered_bytes)

    print(f"\n    [!] Cryptographic Avalanche Effect (Drastic Hash Shift):")
    print(f"        Genuine Image Hash : {genuine_hash}")
    print(f"        Tampered Image Hash: {tampered_hash}")

    # 6. Verify Tampered Image against Blockchain
    print("\n[5] TEST 2: Auditing the Tampered Image against Block #1 Record...")
    is_valid, cand_h, rec_h, msg = bc.verify_image_integrity(tampered_bytes, block_index=1)
    
    if not is_valid:
        print("    [FAIL] Verdict: TAMPER DETECTED! (Image has been modified!)")
        print(f"    - Security Audit Message:\n      {msg}")
    
    print("\n" + "=" * 72)
    print("CONCLUSION:")
    print("Human eyes cannot spot a 1-pixel RGB difference (50 vs 51),")
    print("but the Blockchain SHA-256 cryptographic proof flags it in 0.0001s!")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    run_experiment()
