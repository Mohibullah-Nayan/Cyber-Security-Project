import io
from typing import Union, Tuple, Optional
from PIL import Image
from .crypto_utils import encrypt_message, decrypt_message, CryptoError, TamperDetectedError

MAGIC_HEADER = b"BSTG"  # 4-byte identifier
HEADER_SIZE = len(MAGIC_HEADER) + 1 + 4  # Magic (4) + Flags (1) + Length (4) = 9 bytes


class SteganographyError(Exception):
    """Base exception for Steganography operations."""
    pass


class CapacityExceededError(SteganographyError):
    """Raised when the message is too large for the carrier image."""
    pass


class InvalidStegoImageError(SteganographyError):
    """Raised when an image does not contain a valid steganographic payload."""
    pass


class SteganographyEngine:
    """
    LSB (Least Significant Bit) Image Steganography Engine.
    Embeds binary payload into the least significant bit of RGB color channels.
    Supports optional end-to-end AES-256-GCM encryption.
    """

    @staticmethod
    def get_capacity_bytes(image: Image.Image) -> int:
        """
        Calculates maximum payload capacity in bytes for a given image.
        Each RGB pixel provides 3 bits (1 bit per R, G, B channel).
        """
        total_channels = image.width * image.height * 3
        total_bytes = total_channels // 8
        usable_bytes = max(0, total_bytes - HEADER_SIZE)
        return usable_bytes

    @classmethod
    def encode(
        cls,
        image_input: Union[str, Image.Image, bytes],
        message: str,
        passphrase: Optional[str] = None,
        output_path: Optional[str] = None,
    ) -> Tuple[Image.Image, bytes]:
        """
        Embeds a secret message into an image using LSB encoding.
        
        Args:
            image_input: File path, PIL Image, or image bytes.
            message: Secret text message to hide.
            passphrase: Optional passphrase for AES-256-GCM encryption.
            output_path: Optional path to save the encoded image as PNG.
            
        Returns:
            Tuple of (stego_image_pil, stego_image_bytes)
        """
        if isinstance(image_input, str):
            img = Image.open(image_input)
        elif isinstance(image_input, bytes):
            img = Image.open(io.BytesIO(image_input))
        elif isinstance(image_input, Image.Image):
            img = image_input.copy()
        else:
            raise TypeError("Unsupported image_input type.")

        # Ensure image is in RGB format (handles RGBA, Greyscale, Paletted)
        if img.mode != "RGB":
            img = img.convert("RGB")

        # Prepare payload
        if passphrase:
            flags = 0x01  # Bit 0 set = encrypted
            payload_data = encrypt_message(message, passphrase)
        else:
            flags = 0x00  # Plaintext
            payload_data = message.encode("utf-8")

        payload_length = len(payload_data)
        capacity = cls.get_capacity_bytes(img)
        if payload_length > capacity:
            raise CapacityExceededError(
                f"Payload size ({payload_length} bytes) exceeds image carrier capacity ({capacity} bytes)."
            )

        # Assemble binary frame: MAGIC (4) + FLAGS (1) + LENGTH (4) + PAYLOAD (N)
        header = MAGIC_HEADER + bytes([flags]) + payload_length.to_bytes(4, byteorder="big")
        complete_packet = header + payload_data

        # Convert packet bytes into a continuous bit string
        bit_stream = []
        for byte in complete_packet:
            for i in range(7, -1, -1):
                bit_stream.append((byte >> i) & 1)

        # Embed bits into image pixel RGB channels
        width, height = img.size
        pixels = img.load()
        bit_idx = 0
        total_bits = len(bit_stream)

        for y in range(height):
            for x in range(width):
                if bit_idx >= total_bits:
                    break
                r, g, b = pixels[x, y]
                channels = [r, g, b]

                for c in range(3):
                    if bit_idx < total_bits:
                        # Clear LSB (& ~1) and replace with bit_stream[bit_idx]
                        channels[c] = (channels[c] & ~1) | bit_stream[bit_idx]
                        bit_idx += 1

                pixels[x, y] = (channels[0], channels[1], channels[2])
            if bit_idx >= total_bits:
                break

        # Save to lossless PNG format (lossy formats like JPEG destroy LSBs)
        byte_io = io.BytesIO()
        img.save(byte_io, format="PNG")
        stego_bytes = byte_io.getvalue()

        if output_path:
            with open(output_path, "wb") as f:
                f.write(stego_bytes)

        return img, stego_bytes

    @classmethod
    def decode(
        cls,
        image_input: Union[str, Image.Image, bytes],
        passphrase: Optional[str] = None,
    ) -> str:
        """
        Extracts and decrypts a hidden secret message from a stego image.
        
        Args:
            image_input: File path, PIL Image, or image bytes.
            passphrase: Password used during encoding (required if encrypted).
            
        Returns:
            Extracted secret message string.
        """
        if isinstance(image_input, str):
            img = Image.open(image_input)
        elif isinstance(image_input, bytes):
            img = Image.open(io.BytesIO(image_input))
        elif isinstance(image_input, Image.Image):
            img = image_input
        else:
            raise TypeError("Unsupported image_input type.")

        if img.mode != "RGB":
            img = img.convert("RGB")

        width, height = img.size
        pixels = img.load()

        def bit_generator():
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    yield r & 1
                    yield g & 1
                    yield b & 1

        bits = bit_generator()

        def read_bytes(count: int) -> bytes:
            result = bytearray()
            for _ in range(count):
                byte_val = 0
                for _ in range(8):
                    try:
                        bit = next(bits)
                        byte_val = (byte_val << 1) | bit
                    except StopIteration:
                        raise InvalidStegoImageError("Image stream ended unexpectedly.")
                result.append(byte_val)
            return bytes(result)

        # 1. Verify Magic Header
        magic = read_bytes(len(MAGIC_HEADER))
        if magic != MAGIC_HEADER:
            raise InvalidStegoImageError(
                "No valid steganographic secret message header detected in this image."
            )

        # 2. Read Flags & Payload Length
        flags = read_bytes(1)[0]
        is_encrypted = bool(flags & 0x01)
        length_bytes = read_bytes(4)
        payload_length = int.from_bytes(length_bytes, byteorder="big")

        max_capacity = cls.get_capacity_bytes(img)
        if payload_length > max_capacity:
            raise InvalidStegoImageError("Corrupted steganography header: declared payload exceeds image capacity.")

        # 3. Read Payload
        payload_data = read_bytes(payload_length)

        # 4. Decrypt or Return Plaintext
        if is_encrypted:
            if not passphrase:
                raise ValueError("This secret message is encrypted. A valid passphrase is required to decrypt.")
            return decrypt_message(payload_data, passphrase)
        else:
            return payload_data.decode("utf-8")
