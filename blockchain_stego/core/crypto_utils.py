import hashlib
import os
import math
from typing import Tuple, Union, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidTag, InvalidSignature
from PIL import Image


class CryptoError(Exception):
    """Custom exception for cryptographic failures."""
    pass


class TamperDetectedError(CryptoError):
    """Raised when data integrity or authentication tag validation fails."""
    pass


def calculate_sha256_bytes(data: bytes) -> str:
    """Computes SHA-256 cryptographic hash of arbitrary bytes."""
    return hashlib.sha256(data).hexdigest()


def calculate_sha256_file(filepath: str, chunk_size: int = 65536) -> str:
    """
    Computes SHA-256 cryptographic hash of a file on disk using streaming chunks.
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


def derive_key(passphrase: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """
    Derives a 256-bit symmetric key from a passphrase using PBKDF2-HMAC-SHA256 (NIST SP 800-132).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_message(plaintext: str, passphrase: str) -> bytes:
    """
    Encrypts a plaintext string using AES-256-GCM (Authenticated Encryption).
    Structure: [16B Salt] + [12B Nonce] + [Ciphertext + 16B Auth Tag]
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase, salt)
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    
    return salt + nonce + ciphertext


def decrypt_message(encrypted_payload: bytes, passphrase: str) -> str:
    """
    Decrypts an AES-256-GCM payload and verifies authenticity tag.
    """
    if len(encrypted_payload) < 16 + 12 + 16:
        raise ValueError("Invalid payload length: insufficient bytes for salt, nonce, and tag.")
    
    salt = encrypted_payload[:16]
    nonce = encrypted_payload[16:28]
    ciphertext = encrypted_payload[28:]
    
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    
    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode("utf-8")
    except InvalidTag:
        raise TamperDetectedError(
            "Cryptographic integrity verification failed! Invalid passphrase or modified payload."
        )
    except Exception as e:
        raise CryptoError(f"Decryption failed: {str(e)}")


# ----------------- ASYMMETRIC ECDSA DIGITAL SIGNATURES -----------------

def generate_ecdsa_keypair() -> Tuple[ec.EllipticCurvePrivateKey, str]:
    """
    Generates an ECDSA keypair using curve SECP256R1 (NIST P-256).
    Returns (private_key_obj, public_key_pem_string).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    
    return private_key, pem


def sign_data(arg1: Any, arg2: Any) -> str:
    """
    Signs data using ECDSA-SHA256 and returns signature as hex string.
    Supports either (private_key, data) or (data, private_key).
    """
    if hasattr(arg1, "sign"):
        private_key, data = arg1, arg2
    elif hasattr(arg2, "sign"):
        data, private_key = arg1, arg2
    else:
        raise TypeError("Neither argument provided is a valid ECDSA private key with .sign() method.")

    if isinstance(data, str):
        data_bytes = data.encode("utf-8")
    else:
        data_bytes = data

    signature = private_key.sign(data_bytes, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


def verify_signature(public_key_pem: str, signature_hex: str, data: Union[str, bytes]) -> bool:
    """
    Verifies an ECDSA-SHA256 signature against data using public key PEM string.
    Returns True if valid, False otherwise.
    """
    if not public_key_pem or not signature_hex:
        return False
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        signature_bytes = bytes.fromhex(signature_hex)
        
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        public_key.verify(signature_bytes, data_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


# ----------------- SHANNON ENTROPY FORENSIC METRICS -----------------

def calculate_shannon_entropy(image: Image.Image) -> float:
    """
    Calculates mathematical Shannon Entropy: H = -sum(p * log2(p)).
    Max value for 8-bit image is 8.0 bits/pixel.
    Higher entropy with low variance indicates stealthy, undetectable steganography.
    """
    gray = image.convert("L")
    histogram = gray.histogram()
    total_pixels = sum(histogram)
    if total_pixels == 0:
        return 0.0

    entropy = 0.0
    for count in histogram:
        if count > 0:
            p = count / total_pixels
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# ----------------- PSNR, SSIM & CHI-SQUARE STEGANALYSIS -----------------

def calculate_psnr_ssim(img1: Image.Image, img2: Image.Image) -> Tuple[float, float]:
    """
    Computes Peak Signal-to-Noise Ratio (PSNR in dB) and Structural Similarity Index (SSIM).
    PSNR > 40 dB indicates high fidelity imperceptible to human vision.
    SSIM ranges from -1 to 1 (1.0 = mathematically identical).
    """
    import numpy as np
    arr1 = np.array(img1.convert("RGB"), dtype=np.float64)
    arr2 = np.array(img2.convert("RGB"), dtype=np.float64)

    if arr1.shape != arr2.shape:
        arr2 = np.array(img2.resize(img1.size).convert("RGB"), dtype=np.float64)

    mse = np.mean((arr1 - arr2) ** 2)
    if mse == 0:
        psnr = 100.0  # Perfect identical fidelity
    else:
        psnr = 20 * math.log10(255.0 / math.sqrt(mse))

    # Simplified global SSIM (Wang et al. 2004)
    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2

    mu1 = np.mean(arr1)
    mu2 = np.mean(arr2)
    sigma1_sq = np.var(arr1)
    sigma2_sq = np.var(arr2)
    sigma12 = np.cov(arr1.flatten(), arr2.flatten())[0, 1]

    numerator = (2 * mu1 * mu2 + c1) * (2 * sigma12 + c2)
    denominator = (mu1 ** 2 + mu2 ** 2 + c1) * (sigma1_sq + sigma2_sq + c2)
    ssim = numerator / denominator if denominator != 0 else 1.0

    return round(psnr, 2), round(float(ssim), 4)


def calculate_chi_square_steganalysis(image: Image.Image) -> dict:
    """
    Executes Westfeld-Pfitzmann Chi-Square (χ²) Steganalysis test for LSB embedding.
    Analyzes Pairs of Values (PoVs: 2k, 2k+1).
    Returns chi_square statistic, degree of freedom, and detection confidence.
    """
    import numpy as np
    arr = np.array(image.convert("L")).flatten()
    counts = np.bincount(arr, minlength=256)

    chi_square = 0.0
    valid_pairs = 0
    for k in range(128):
        y_2k = counts[2 * k]
        y_2k1 = counts[2 * k + 1]
        sum_pair = y_2k + y_2k1
        if sum_pair > 0:
            expected = sum_pair / 2.0
            chi_square += ((y_2k - expected) ** 2 + (y_2k1 - expected) ** 2) / expected
            valid_pairs += 1

    stego_prob = 1.0 / (1.0 + math.exp(-0.005 * (chi_square - 128))) if valid_pairs > 0 else 0.0

    return {
        "chi_square_statistic": round(chi_square, 2),
        "degrees_of_freedom": valid_pairs,
        "stego_detection_probability": round(min(1.0, max(0.0, stego_prob)), 4),
        "status": "PASS (Steganographically Concealed)" if stego_prob < 0.6 else "SUSPICIOUS (Statistical Trace Detected)",
    }
