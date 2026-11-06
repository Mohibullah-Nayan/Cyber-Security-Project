import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from .crypto_utils import calculate_sha256_bytes


class Block:
    """
    Represents an immutable single block in the ledger.
    Contains cryptographic binding between image hash, metadata, previous block,
    Proof-of-Work nonce, and ECDSA digital signature for non-repudiation.
    """

    def __init__(
        self,
        index: int,
        timestamp: Optional[str] = None,
        image_hash: str = "",
        image_name: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        previous_hash: str = "0",
        nonce: int = 0,
        sender_public_key: str = "",
        signature: str = "",
        merkle_root: str = "",
        block_hash: Optional[str] = None,
    ):
        self.index = index
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.image_hash = image_hash
        self.image_name = image_name
        self.metadata = metadata or {}
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.sender_public_key = sender_public_key
        self.signature = signature
        self.merkle_root = merkle_root or (image_hash if image_hash else "0" * 64)
        self.hash = block_hash or self.calculate_hash()

    def calculate_hash(self) -> str:
        """
        Computes deterministic SHA-256 hash of the block's content.
        Uses sorted keys for metadata JSON to guarantee canonical hashing.
        """
        block_content = {
            "index": self.index,
            "timestamp": self.timestamp,
            "image_hash": self.image_hash,
            "image_name": self.image_name,
            "metadata": self.metadata,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "sender_public_key": self.sender_public_key,
            "signature": self.signature,
            "merkle_root": self.merkle_root,
        }
        encoded = json.dumps(block_content, sort_keys=True).encode("utf-8")
        return calculate_sha256_bytes(encoded)

    def mine_block(self, difficulty: int) -> None:
        """
        Executes Proof-of-Work consensus algorithm.
        Increments nonce until hash satisfies target difficulty (number of leading zeros).
        """
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes block to a dictionary."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "image_hash": self.image_hash,
            "image_name": self.image_name,
            "metadata": self.metadata,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "sender_public_key": self.sender_public_key,
            "signature": self.signature,
            "merkle_root": self.merkle_root,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Block":
        """Instantiates a Block from a dictionary."""
        return cls(
            index=data["index"],
            timestamp=data["timestamp"],
            image_hash=data["image_hash"],
            image_name=data.get("image_name", ""),
            metadata=data.get("metadata", {}),
            previous_hash=data["previous_hash"],
            nonce=data["nonce"],
            sender_public_key=data.get("sender_public_key", ""),
            signature=data.get("signature", ""),
            merkle_root=data.get("merkle_root", ""),
            block_hash=data["hash"],
        )

    def __repr__(self) -> str:
        return (
            f"<Block #{self.index} [Hash: {self.hash[:12]}...] "
            f"ImageHash: {self.image_hash[:12]}... Nonce: {self.nonce}>"
        )
