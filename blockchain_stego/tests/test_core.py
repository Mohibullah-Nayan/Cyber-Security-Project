import io
import os
import tempfile
import unittest
from PIL import Image

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.crypto_utils import (
    calculate_sha256_bytes,
    calculate_sha256_file,
    encrypt_message,
    decrypt_message,
    generate_ecdsa_keypair,
    sign_data,
    verify_signature,
    calculate_shannon_entropy,
    calculate_psnr_ssim,
    calculate_chi_square_steganalysis,
    TamperDetectedError,
)
from core.merkle_tree import MerkleTree
from core.steganography import (
    SteganographyEngine,
    CapacityExceededError,
    InvalidStegoImageError,
)
from core.block import Block
from core.blockchain import Blockchain


def create_sample_image(width=100, height=100, color=(128, 64, 200)) -> Image.Image:
    """Creates a simple RGB test carrier image."""
    return Image.new("RGB", (width, height), color=color)


class TestCryptoAndSteganography(unittest.TestCase):
    def test_aes_encryption_decryption_success(self):
        message = "Top Secret: Cryptographic Blockchain Stego 2026!"
        passphrase = "SuperSecurePassword#123"
        ciphertext = encrypt_message(message, passphrase)

        decrypted = decrypt_message(ciphertext, passphrase)
        self.assertEqual(decrypted, message)

    def test_aes_decryption_wrong_password_fails(self):
        message = "Confidential Data"
        passphrase = "CorrectPassword"
        ciphertext = encrypt_message(message, passphrase)

        with self.assertRaises(TamperDetectedError):
            decrypt_message(ciphertext, "WrongPassword")

    def test_ecdsa_signature_verification(self):
        priv_key, pub_pem = generate_ecdsa_keypair()
        payload = "SHA256:d5a6b7c8e9f0123456789abcdef0"
        
        signature = sign_data(priv_key, payload)
        self.assertTrue(verify_signature(pub_pem, signature, payload))
        
        # Test failure on forged payload
        self.assertFalse(verify_signature(pub_pem, signature, "FORGED_PAYLOAD"))

    def test_shannon_entropy_calculation(self):
        img = create_sample_image(50, 50, color=(100, 150, 200))
        entropy = calculate_shannon_entropy(img)
        self.assertIsInstance(entropy, float)
        self.assertGreaterEqual(entropy, 0.0)
        self.assertLessEqual(entropy, 8.0)

    def test_psnr_and_ssim(self):
        img1 = create_sample_image(60, 60, color=(50, 100, 150))
        stego, _ = SteganographyEngine.encode(img1, "Secret payload")
        psnr, ssim = calculate_psnr_ssim(img1, stego)
        self.assertGreater(psnr, 40.0)
        self.assertGreater(ssim, 0.95)

    def test_chi_square_steganalysis(self):
        img = create_sample_image(60, 60, color=(80, 120, 160))
        res = calculate_chi_square_steganalysis(img)
        self.assertIn("chi_square_statistic", res)
        self.assertIn("stego_detection_probability", res)

    def test_merkle_tree_proof_and_verification(self):
        leaves = ["hash1", "hash2", "hash3", "hash4"]
        tree = MerkleTree(leaves)
        root = tree.get_merkle_root()
        self.assertEqual(len(root), 64)

        # Generate proof for leaf 1 ("hash2")
        proof = tree.generate_proof(1)
        # Expected leaf 1 hash
        leaf1_hash = calculate_sha256_bytes(b"hash2") if len("hash2") != 64 else "hash2"
        # Verify proof
        self.assertTrue(MerkleTree.verify_proof(leaf1_hash, proof, root))

    def test_stego_encode_decode_plaintext(self):
        img = create_sample_image(80, 80)
        secret = "Hello Blockchain Steganography!"
        stego_img, stego_bytes = SteganographyEngine.encode(img, secret)

        extracted = SteganographyEngine.decode(stego_img)
        self.assertEqual(extracted, secret)

    def test_stego_encode_decode_encrypted(self):
        img = create_sample_image(120, 120)
        secret = "Mission Critical Classified Information"
        key = "Valkyrie-Pass-99"

        stego_img, stego_bytes = SteganographyEngine.encode(img, secret, passphrase=key)
        extracted = SteganographyEngine.decode(stego_img, passphrase=key)
        self.assertEqual(extracted, secret)

        with self.assertRaises(TamperDetectedError):
            SteganographyEngine.decode(stego_img, passphrase="WrongKey")


class TestBlockchainAndTamperDetection(unittest.TestCase):
    def test_blockchain_mining_and_validity(self):
        bc = Blockchain(difficulty=2)
        self.assertEqual(len(bc.chain), 1)

        priv_key, pub_pem = generate_ecdsa_keypair()
        dummy_hash = calculate_sha256_bytes(b"image_1_content")
        sig = sign_data(priv_key, dummy_hash)

        b1 = bc.add_block(dummy_hash, "intel_report.png", {"agent": "007"}, sender_public_key=pub_pem, signature=sig)
        self.assertEqual(b1.index, 1)
        self.assertTrue(b1.hash.startswith("00"))

        is_valid, err = bc.is_chain_valid()
        self.assertTrue(is_valid)

        # Check signature verification on block
        sig_ok, _ = bc.verify_block_signature(1)
        self.assertTrue(sig_ok)

    def test_p2p_consensus_simulation(self):
        bc = Blockchain(difficulty=2)
        valid_block = Block(
            index=1,
            image_hash="abc",
            previous_hash=bc.chain[0].hash,
        )
        valid_block.mine_block(2)
        
        result = bc.simulate_p2p_consensus(valid_block, node_count=4)
        self.assertTrue(result["consensus_reached"])
        self.assertEqual(result["accepted_count"], 4)

    def test_detect_image_pixel_tampering(self):
        bc = Blockchain(difficulty=2)
        img = create_sample_image(100, 100)
        secret = "Blockchain immutable payload"

        stego_img, stego_bytes = SteganographyEngine.encode(img, secret)
        original_hash = calculate_sha256_bytes(stego_bytes)
        block = bc.add_block(original_hash, "secure_stego.png")

        # 1. Genuine image passes
        is_ok, cand_h, rec_h, msg = bc.verify_image_integrity(stego_bytes, block.index)
        self.assertTrue(is_ok)

        # 2. Tampered image fails
        tampered_img = stego_img.copy()
        tampered_pixels = tampered_img.load()
        tampered_pixels[99, 99] = (255, 0, 0)

        buf = io.BytesIO()
        tampered_img.save(buf, format="PNG")
        tampered_bytes = buf.getvalue()

        is_ok, cand_h, rec_h, msg = bc.verify_image_integrity(tampered_bytes, block.index)
        self.assertFalse(is_ok)
        self.assertIn("TAMPER DETECTED", msg)


if __name__ == "__main__":
    unittest.main()
