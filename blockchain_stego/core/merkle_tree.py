import hashlib
from typing import List, Dict, Any, Tuple, Optional


def sha256_hash(data: str) -> str:
    """Computes SHA-256 hash of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class MerkleTree:
    """
    Cryptographic Binary Merkle Tree for batch image and transaction hashing.
    Enforces logarithmic verification O(log N) through Merkle Proofs.
    """

    def __init__(self, leaves: List[str]):
        """
        Initializes Merkle Tree from a list of leaf hashes.
        If leaves is empty, root is initialized to 64 zeros.
        """
        self.leaves = leaves if leaves else ["0" * 64]
        self.levels: List[List[str]] = []
        self.root = self._build_tree()

    def _build_tree(self) -> str:
        current_level = [leaf if len(leaf) == 64 else sha256_hash(leaf) for leaf in self.leaves]
        self.levels.append(current_level)

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = left  # Duplicate odd leaf (Bitcoin standard)
                combined_hash = sha256_hash(left + right)
                next_level.append(combined_hash)
            current_level = next_level
            self.levels.append(current_level)

        return self.levels[-1][0]

    def get_merkle_root(self) -> str:
        """Returns 64-character hex Merkle Root."""
        return self.root

    def generate_proof(self, leaf_index: int) -> List[Dict[str, str]]:
        """
        Generates Merkle Audit Proof for the leaf at leaf_index.
        Returns list of sibling hashes with their position ('left' or 'right').
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError("Leaf index out of bounds.")

        proof = []
        idx = leaf_index

        for level in self.levels[:-1]:
            if idx % 2 == 0:
                # Leaf is left child; sibling is right (or self if odd tail)
                sibling_idx = idx + 1 if idx + 1 < len(level) else idx
                proof.append({"position": "right", "hash": level[sibling_idx]})
            else:
                # Leaf is right child; sibling is left
                proof.append({"position": "left", "hash": level[idx - 1]})
            idx //= 2

        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Dict[str, str]], expected_root: str) -> bool:
        """
        Verifies a candidate leaf hash against the expected Merkle Root in O(log N) steps.
        """
        current_hash = leaf_hash
        for sibling in proof:
            sibling_hash = sibling["hash"]
            if sibling["position"] == "left":
                current_hash = sha256_hash(sibling_hash + current_hash)
            else:
                current_hash = sha256_hash(current_hash + sibling_hash)
        return current_hash == expected_root
