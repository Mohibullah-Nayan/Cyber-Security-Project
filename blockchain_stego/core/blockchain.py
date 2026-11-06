import os
import json
from typing import List, Dict, Any, Tuple, Optional, Union
from .block import Block
from .crypto_utils import (
    calculate_sha256_bytes,
    calculate_sha256_file,
    verify_signature,
)


class Blockchain:
    """
    Manages an append-only distributed ledger for image secret messaging.
    Enforces Proof-of-Work consensus, chain integrity validation, ECDSA verification,
    and P2P Byzantine consensus simulation.
    """

    GENESIS_PREVIOUS_HASH = "0" * 64

    def __init__(self, difficulty: int = 2):
        self.chain: List[Block] = []
        self.difficulty: int = difficulty
        self._initialize_genesis_block()

    def _initialize_genesis_block(self) -> None:
        """Creates and mines the initial Genesis Block if chain is empty."""
        if not self.chain:
            genesis_block = Block(
                index=0,
                image_hash="GENESIS_NULL_IMAGE_HASH",
                image_name="Genesis",
                metadata={"description": "Genesis Block of Stego-Secured Blockchain Ledger"},
                previous_hash=self.GENESIS_PREVIOUS_HASH,
            )
            genesis_block.mine_block(self.difficulty)
            self.chain.append(genesis_block)

    def get_latest_block(self) -> Block:
        """Returns the most recently added block in the chain."""
        return self.chain[-1]

    def add_block(
        self,
        image_hash: str,
        image_name: str,
        metadata: Optional[Dict[str, Any]] = None,
        sender_public_key: str = "",
        signature: str = "",
        merkle_root: str = "",
    ) -> Block:
        """
        Mines and appends a new block recording the cryptographic proof, Merkle root, and ECDSA signature.
        """
        prev_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            image_hash=image_hash,
            image_name=image_name,
            metadata=metadata or {},
            previous_hash=prev_block.hash,
            sender_public_key=sender_public_key,
            signature=signature,
            merkle_root=merkle_root,
        )
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self) -> Tuple[bool, Optional[str]]:
        """
        Performs a full cryptographic audit on the entire ledger.
        """
        target = "0" * self.difficulty

        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # 1. Recalculate hash to detect mutation
            recalculated_hash = current.calculate_hash()
            if current.hash != recalculated_hash:
                return (
                    False,
                    f"TAMPER DETECTED at Block #{current.index}: Stored hash '{current.hash}' "
                    f"does not match recalculated content hash '{recalculated_hash}'.",
                )

            # 2. Verify chain linkage
            if current.previous_hash != previous.hash:
                return (
                    False,
                    f"BROKEN CHAIN at Block #{current.index}: Previous hash pointer '{current.previous_hash}' "
                    f"does not match Block #{previous.index} hash '{previous.hash}'.",
                )

            # 3. Verify Proof-of-Work condition
            if not current.hash.startswith(target):
                return (
                    False,
                    f"INVALID PROOF-OF-WORK at Block #{current.index}: Hash '{current.hash}' "
                    f"fails difficulty target requirement ('{target}').",
                )

        return True, None

    def verify_block_signature(self, block_index: int) -> Tuple[bool, str]:
        """
        Verifies ECDSA digital signature of a block to confirm sender authenticity.
        """
        if block_index < 0 or block_index >= len(self.chain):
            return False, "Block does not exist."

        block = self.chain[block_index]
        if not block.sender_public_key or not block.signature:
            return False, "Block does not contain an ECDSA signature."

        is_valid = verify_signature(block.sender_public_key, block.signature, block.image_hash)
        if is_valid:
            return True, f"ECDSA Signature Authenticated: Valid signature for Block #{block_index}."
        else:
            return False, f"Signature Mismatch: Invalid digital signature on Block #{block_index}!"

    def verify_image_integrity(
        self,
        image_input: Union[str, bytes],
        block_index: int,
    ) -> Tuple[bool, str, str, str]:
        """
        Verifies if an image has been altered or tampered with against its immutable ledger record.
        """
        if block_index < 0 or block_index >= len(self.chain):
            return False, "", "", f"Block index #{block_index} does not exist in ledger."

        target_block = self.chain[block_index]

        if isinstance(image_input, str):
            if not os.path.exists(image_input):
                return False, "", target_block.image_hash, f"File not found: {image_input}"
            candidate_hash = calculate_sha256_file(image_input)
        elif isinstance(image_input, bytes):
            candidate_hash = calculate_sha256_bytes(image_input)
        else:
            raise TypeError("image_input must be file path or bytes.")

        if candidate_hash == target_block.image_hash:
            return (
                True,
                candidate_hash,
                target_block.image_hash,
                f"VERIFIED: Candidate image SHA-256 matches Block #{block_index} record exactly. Zero tampering.",
            )
        else:
            return (
                False,
                candidate_hash,
                target_block.image_hash,
                f"TAMPER DETECTED! Candidate image hash ({candidate_hash}) differs from immutable "
                f"Block #{block_index} record ({target_block.image_hash}). Image was modified!",
            )

    def find_block_by_image_hash(self, image_hash: str) -> Optional[Block]:
        """Searches the chain for a block containing the specified image hash."""
        for block in self.chain:
            if block.image_hash == image_hash:
                return block
        return None

    def simulate_tamper_block_data(self, block_index: int, new_image_hash: str) -> None:
        """Educational helper to modify block payload in-place."""
        if 0 <= block_index < len(self.chain):
            self.chain[block_index].image_hash = new_image_hash

    def simulate_p2p_consensus(
        self, candidate_block: Block, node_count: int = 4
    ) -> Dict[str, Any]:
        """
        Simulates decentralized P2P consensus across independent network nodes.
        Checks Proof-of-Work, previous hash linkage, and content integrity.
        Returns voting consensus results (Byzantine Fault Tolerance).
        """
        node_names = [f"Peer-Node-{chr(65 + i)}" for i in range(node_count)]
        votes = {}
        target = "0" * self.difficulty
        prev = self.get_latest_block()

        # Validation rules:
        is_pow_valid = candidate_block.hash.startswith(target)
        is_link_valid = candidate_block.previous_hash == prev.hash
        is_content_valid = candidate_block.calculate_hash() == candidate_block.hash

        block_is_healthy = is_pow_valid and is_link_valid and is_content_valid

        for name in node_names:
            # Honest nodes vote according to cryptographic validity
            votes[name] = "ACCEPTED" if block_is_healthy else "REJECTED"

        accepted_count = sum(1 for v in votes.values() if v == "ACCEPTED")
        consensus_reached = accepted_count > (node_count // 2)

        return {
            "node_count": node_count,
            "votes": votes,
            "accepted_count": accepted_count,
            "consensus_reached": consensus_reached,
            "consensus_pct": (accepted_count / node_count) * 100,
            "block_healthy": block_is_healthy,
        }

    def to_json(self) -> str:
        """Serializes the entire blockchain ledger to formatted JSON."""
        return json.dumps(
            {
                "difficulty": self.difficulty,
                "chain": [block.to_dict() for block in self.chain],
            },
            indent=4,
        )

    def save_ledger(self, filepath: str) -> None:
        """Saves blockchain ledger to a JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    @classmethod
    def load_ledger(cls, filepath: str) -> "Blockchain":
        """Loads and reconstructs a blockchain ledger from a JSON file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        instance = cls(difficulty=data.get("difficulty", 2))
        instance.chain = [Block.from_dict(b) for b in data["chain"]]
        return instance
