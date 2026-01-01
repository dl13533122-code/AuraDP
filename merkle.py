"""
AuraLDP Merkle Tree Implementation
- Binary Merkle tree with SHA-256
- Proof generation and verification
- Handles non-power-of-2 leaf counts
"""

from typing import List, Tuple, Optional
from dataclasses import dataclass
from models import H, MerkleDirection, MerkleProof


def merkle_hash_pair(left: bytes, right: bytes) -> bytes:
    """Hash two nodes together"""
    return H(left, right, domain="AuraLDP-merkle")


class MerkleTree:
    """
    Binary Merkle Tree with proof generation.
    Handles non-power-of-2 leaf counts by propagating odd nodes up.
    """

    def __init__(self, leaves: List[bytes]):
        """
        Build Merkle tree from leaf hashes.

        Args:
            leaves: List of leaf hashes (already hashed data)
        """
        if not leaves:
            raise ValueError("Cannot create Merkle tree with no leaves")

        self.leaves = leaves
        self.n_leaves = len(leaves)
        self._build_tree()

    def _build_tree(self):
        """Build the tree structure"""
        self.levels: List[List[bytes]] = [self.leaves.copy()]
        current_level = self.leaves.copy()

        while len(current_level) > 1:
            next_level = []
            i = 0

            while i < len(current_level):
                if i + 1 < len(current_level):
                    combined = merkle_hash_pair(current_level[i], current_level[i + 1])
                    next_level.append(combined)
                    i += 2
                else:
                    next_level.append(current_level[i])
                    i += 1

            self.levels.append(next_level)
            current_level = next_level

        self.root = current_level[0]

    def get_root(self) -> bytes:
        """Get the Merkle root"""
        return self.root

    def get_proof(self, leaf_index: int) -> MerkleProof:
        """
        Generate inclusion proof for a leaf.

        Args:
            leaf_index: Index of the leaf (0-based)

        Returns:
            MerkleProof with path from leaf to root
        """
        if leaf_index < 0 or leaf_index >= self.n_leaves:
            raise ValueError(f"Leaf index {leaf_index} out of range [0, {self.n_leaves})")

        path: List[Tuple[MerkleDirection, bytes]] = []
        current_index = leaf_index

        for level in self.levels[:-1]:
            level_size = len(level)

            if current_index % 2 == 0:
                if current_index + 1 < level_size:
                    sibling = level[current_index + 1]
                    path.append((MerkleDirection.RIGHT, sibling))
            else:
                sibling = level[current_index - 1]
                path.append((MerkleDirection.LEFT, sibling))

            current_index //= 2

        return MerkleProof(
            leaf_index=leaf_index,
            leaf_hash=self.leaves[leaf_index],
            path=path
        )

    def verify_proof(self, proof: MerkleProof, expected_root: bytes) -> bool:
        """Verify a Merkle inclusion proof"""
        return verify_merkle_proof(proof, expected_root)


def verify_merkle_proof(proof: MerkleProof, expected_root: bytes) -> bool:
    """
    Verify a Merkle inclusion proof.

    Args:
        proof: The Merkle proof to verify
        expected_root: Expected Merkle root

    Returns:
        True if proof is valid
    """
    current_hash = proof.leaf_hash

    for direction, sibling in proof.path:
        if direction == MerkleDirection.LEFT:
            current_hash = merkle_hash_pair(sibling, current_hash)
        else:
            current_hash = merkle_hash_pair(current_hash, sibling)

    return current_hash == expected_root


def compute_merkle_root(leaves: List[bytes]) -> bytes:
    """Compute Merkle root without storing full tree"""
    if not leaves:
        raise ValueError("Cannot compute root with no leaves")

    if len(leaves) == 1:
        return leaves[0]

    tree = MerkleTree(leaves)
    return tree.get_root()


@dataclass
class MerkleTreeCache:
    """
    Cached Merkle tree that supports efficient appends and proof generation.
    Used by servers to maintain state during a round.
    """
    leaves: List[bytes]
    tree: Optional[MerkleTree]
    is_finalized: bool

    def __init__(self):
        self.leaves = []
        self.tree = None
        self.is_finalized = False

    def append(self, leaf_hash: bytes) -> int:
        """
        Append a leaf and return its index.
        Tree must be rebuilt after all appends.
        """
        if self.is_finalized:
            raise RuntimeError("Cannot append to finalized tree")

        index = len(self.leaves)
        self.leaves.append(leaf_hash)
        self.tree = None
        return index

    def finalize(self) -> bytes:
        """
        Finalize the tree and return root.
        No more appends allowed after this.
        """
        if not self.leaves:
            raise RuntimeError("Cannot finalize empty tree")

        self.tree = MerkleTree(self.leaves)
        self.is_finalized = True
        return self.tree.get_root()

    def get_proof(self, index: int) -> MerkleProof:
        """Get proof for a leaf (must be finalized)"""
        if not self.is_finalized or self.tree is None:
            raise RuntimeError("Tree must be finalized before getting proofs")

        return self.tree.get_proof(index)

    def get_root(self) -> bytes:
        """Get the root (must be finalized)"""
        if not self.is_finalized or self.tree is None:
            raise RuntimeError("Tree must be finalized before getting root")

        return self.tree.get_root()

    def count(self) -> int:
        """Get number of leaves"""
        return len(self.leaves)


def test_merkle_tree():
    """Basic tests for Merkle tree"""
    leaves = [H(f"leaf{i}".encode()) for i in range(8)]
    tree = MerkleTree(leaves)

    print(f"Root (8 leaves): {tree.get_root().hex()[:16]}...")

    for i in range(len(leaves)):
        proof = tree.get_proof(i)
        assert tree.verify_proof(proof, tree.get_root()), f"Proof {i} failed"

    leaves_5 = [H(f"leaf{i}".encode()) for i in range(5)]
    tree_5 = MerkleTree(leaves_5)

    print(f"Root (5 leaves): {tree_5.get_root().hex()[:16]}...")

    for i in range(len(leaves_5)):
        proof = tree_5.get_proof(i)
        assert tree_5.verify_proof(proof, tree_5.get_root()), f"Proof {i} failed for 5-leaf tree"

    leaves_1 = [H(b"single")]
    tree_1 = MerkleTree(leaves_1)
    proof = tree_1.get_proof(0)
    assert tree_1.verify_proof(proof, tree_1.get_root()), "Single leaf proof failed"

    print("All Merkle tree tests passed!")


if __name__ == "__main__":
    test_merkle_tree()
