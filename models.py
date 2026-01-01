"""
AuraLDP Data Models
Canonical serialization for all structures
Support for TNO threshold Paillier integration
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import struct
import hashlib


# ============================================================================
# Canonical Serialization Helpers
# ============================================================================

def canonical_bytes(data: bytes) -> bytes:
    """Length-prefixed bytes: 4-byte big-endian length + data"""
    return struct.pack(">I", len(data)) + data


def canonical_int(val: int, byte_length: int = 4) -> bytes:
    """Fixed-width big-endian integer"""
    return val.to_bytes(byte_length, "big")


def canonical_str(s: str) -> bytes:
    """UTF-8 encoded length-prefixed string"""
    encoded = s.encode("utf-8")
    return canonical_bytes(encoded)


def canonical_bigint(val: int) -> bytes:
    """Variable-length big integer serialization"""
    if val == 0:
        return canonical_bytes(b'\x00')
    byte_len = (val.bit_length() + 7) // 8
    return canonical_bytes(val.to_bytes(byte_len, "big"))


def H(*parts: bytes, domain: str = "") -> bytes:
    """Domain-separated SHA-256 hash"""
    h = hashlib.sha256()
    if domain:
        h.update(canonical_str(domain))
    for p in parts:
        h.update(p)
    return h.digest()


def bigint_to_bytes(val: int) -> bytes:
    """Convert big integer to bytes"""
    if val == 0:
        return b'\x00'
    byte_len = (val.bit_length() + 7) // 8
    return val.to_bytes(byte_len, "big")


def bytes_to_bigint(data: bytes) -> int:
    """Convert bytes to big integer"""
    return int.from_bytes(data, "big")


# ============================================================================
# Token & Record (User Submission)
# ============================================================================

@dataclass
class Token:
    """One-time token from Issuer"""
    m: bytes              # Random nonce
    h: bytes              # H("AuraLDP-bind" || rid || c)
    sig: bytes            # Issuer signature on (rid || server_id || m || h)

    def to_bytes(self) -> bytes:
        return canonical_bytes(self.m) + canonical_bytes(self.h) + canonical_bytes(self.sig)

    @classmethod
    def from_bytes(cls, data: bytes) -> Tuple["Token", bytes]:
        offset = 0
        m_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        m = data[offset:offset+m_len]
        offset += m_len

        h_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        h_val = data[offset:offset+h_len]
        offset += h_len

        sig_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        sig = data[offset:offset+sig_len]
        offset += sig_len

        return cls(m=m, h=h_val, sig=sig), data[offset:]


@dataclass
class Record:
    """User submission record"""
    rid: bytes            # Round ID
    server_id: int        # Target server (bound in token)
    req_id: bytes         # 128-bit random request ID
    c: bytes              # Paillier ciphertext (serialized)
    tok: Token

    def to_bytes(self) -> bytes:
        return (
            canonical_bytes(self.rid) +
            canonical_int(self.server_id) +
            canonical_bytes(self.req_id) +
            canonical_bytes(self.c) +
            self.tok.to_bytes()
        )

    def compute_tag(self) -> bytes:
        """Derive tag = H("AuraLDP-tag" || rid || m)"""
        return H(self.rid, self.tok.m, domain="AuraLDP-tag")

    def compute_binding_hash(self) -> bytes:
        """Compute h = H("AuraLDP-bind" || rid || c)"""
        return H(self.rid, self.c, domain="AuraLDP-bind")

    def compute_leaf_hash(self) -> bytes:
        """Compute leaf = H("AuraLDP-leaf" || rid || tag || c || h)"""
        tag = self.compute_tag()
        return H(self.rid, tag, self.c, self.tok.h, domain="AuraLDP-leaf")


# ============================================================================
# Batch Statement (Server publishes after round ends)
# ============================================================================

@dataclass
class BatchStatement:
    """Server's batch statement for a round"""
    rid: bytes
    server_id: int
    n_i: int              # Number of records
    root_i: bytes         # Merkle root
    C_i: bytes            # Serialized aggregate ciphertext

    def to_bytes(self) -> bytes:
        return (
            canonical_bytes(self.rid) +
            canonical_int(self.server_id) +
            canonical_int(self.n_i, 8) +
            canonical_bytes(self.root_i) +
            canonical_bytes(self.C_i)
        )

    def compute_hash(self) -> bytes:
        """H("AuraLDP-stmt" || stmt)"""
        return H(self.to_bytes(), domain="AuraLDP-stmt")


@dataclass
class SignedBatchStatement:
    """Signed batch statement"""
    stmt: BatchStatement
    sig_server: bytes     # Server's signature

    def to_bytes(self) -> bytes:
        return self.stmt.to_bytes() + canonical_bytes(self.sig_server)


# ============================================================================
# Seed Commit-Reveal Protocol
# ============================================================================

@dataclass
class SeedCommit:
    """Commitment to random seed contribution"""
    rid: bytes
    server_id: int
    commit: bytes         # H(random_value || nonce)

    def to_bytes(self) -> bytes:
        return (
            canonical_bytes(self.rid) +
            canonical_int(self.server_id) +
            canonical_bytes(self.commit)
        )


@dataclass
class SeedReveal:
    """Reveal of random seed contribution"""
    rid: bytes
    server_id: int
    random_value: bytes
    nonce: bytes

    def to_bytes(self) -> bytes:
        return (
            canonical_bytes(self.rid) +
            canonical_int(self.server_id) +
            canonical_bytes(self.random_value) +
            canonical_bytes(self.nonce)
        )

    def compute_commit(self) -> bytes:
        """Verify commitment matches reveal"""
        return H(self.random_value, self.nonce, domain="AuraLDP-commit")


@dataclass
class SeedCert:
    """Certified audit seed"""
    rid: bytes
    seed_rid: bytes       # Combined seed
    h_seed: bytes         # H("AuraLDP-seed" || rid || seed_rid)
    sigs: Dict[int, bytes]  # server_id -> signature on h_seed

    def to_bytes(self) -> bytes:
        sig_data = b""
        for sid in sorted(self.sigs.keys()):
            sig_data += canonical_int(sid) + canonical_bytes(self.sigs[sid])
        return (
            canonical_bytes(self.rid) +
            canonical_bytes(self.seed_rid) +
            canonical_bytes(self.h_seed) +
            canonical_int(len(self.sigs)) +
            sig_data
        )


# ============================================================================
# Audit PASS Approval
# ============================================================================

@dataclass
class PASSApproval:
    """Auditor's approval for a batch"""
    rid: bytes
    audited_server_id: int
    n_i: int
    root_i: bytes
    C_i: bytes
    h_seed: bytes
    sig_auditor: bytes

    def to_bytes(self) -> bytes:
        return (
            canonical_bytes(self.rid) +
            canonical_int(self.audited_server_id) +
            canonical_int(self.n_i, 8) +
            canonical_bytes(self.root_i) +
            canonical_bytes(self.C_i) +
            canonical_bytes(self.h_seed) +
            canonical_bytes(self.sig_auditor)
        )

    def compute_message(self) -> bytes:
        """Message that auditor signs"""
        return H(
            self.rid,
            canonical_int(self.audited_server_id),
            canonical_int(self.n_i, 8),
            self.root_i,
            self.C_i,
            self.h_seed,
            domain="AuraLDP-PASS"
        )


# ============================================================================
# Global Statement & Final Certificate
# ============================================================================

@dataclass
class GlobalStatement:
    """Aggregated global statement"""
    rid: bytes
    h_seed: bytes
    I_acc: List[int]      # Accepted server IDs
    batch_hashes: Dict[int, bytes]  # server_id -> H(stmt_i)
    C_glob: bytes         # Serialized aggregate ciphertext
    n_glob: int           # Sum of all n_i

    def to_bytes(self) -> bytes:
        i_acc_bytes = b"".join(canonical_int(i) for i in sorted(self.I_acc))
        batch_bytes = b""
        for sid in sorted(self.batch_hashes.keys()):
            batch_bytes += canonical_int(sid) + canonical_bytes(self.batch_hashes[sid])

        return (
            canonical_bytes(self.rid) +
            canonical_bytes(self.h_seed) +
            canonical_int(len(self.I_acc)) +
            i_acc_bytes +
            canonical_int(len(self.batch_hashes)) +
            batch_bytes +
            canonical_bytes(self.C_glob) +
            canonical_int(self.n_glob, 8)
        )

    def compute_hash(self) -> bytes:
        """h_glob = H("AuraLDP-glob" || globStmt)"""
        return H(self.to_bytes(), domain="AuraLDP-glob")


@dataclass
class FinalCert:
    """Final certificate with threshold signatures"""
    glob_stmt: GlobalStatement
    h_glob: bytes
    fin_sigs: Dict[int, bytes]  # server_id -> signature

    def to_bytes(self) -> bytes:
        sig_data = b""
        for sid in sorted(self.fin_sigs.keys()):
            sig_data += canonical_int(sid) + canonical_bytes(self.fin_sigs[sid])
        return (
            self.glob_stmt.to_bytes() +
            canonical_bytes(self.h_glob) +
            canonical_int(len(self.fin_sigs)) +
            sig_data
        )

    @staticmethod
    def compute_finality_message(rid: bytes, h_glob: bytes) -> bytes:
        """Message that servers sign for finality"""
        return H(rid, h_glob, b"FINAL", domain="AuraLDP-finality")


# ============================================================================
# Threshold Decryption Share (TNO compatible)
# ============================================================================

@dataclass
class DecryptShare:
    """Decryption share from a server (TNO format)"""
    rid: bytes
    h_glob: bytes
    server_id: int
    partial_decryption: bytes  # Serialized partial decryption
    proof: bytes               # Zero-knowledge proof (if available)

    def to_bytes(self) -> bytes:
        return (
            canonical_bytes(self.rid) +
            canonical_bytes(self.h_glob) +
            canonical_int(self.server_id) +
            canonical_bytes(self.partial_decryption) +
            canonical_bytes(self.proof)
        )


# ============================================================================
# Merkle Proof
# ============================================================================

class MerkleDirection(Enum):
    LEFT = 0
    RIGHT = 1


@dataclass
class MerkleProof:
    """Merkle inclusion proof"""
    leaf_index: int
    leaf_hash: bytes
    path: List[Tuple[MerkleDirection, bytes]]  # (direction, sibling_hash)

    def to_bytes(self) -> bytes:
        path_data = b""
        for direction, sibling in self.path:
            path_data += canonical_int(direction.value, 1) + canonical_bytes(sibling)
        return (
            canonical_int(self.leaf_index, 8) +
            canonical_bytes(self.leaf_hash) +
            canonical_int(len(self.path)) +
            path_data
        )


# ============================================================================
# Audit Open Response
# ============================================================================

@dataclass
class AuditOpenItem:
    """Response item for audit open request"""
    index: int
    c: bytes              # Ciphertext
    tok: Token            # Token
    merkle_proof: MerkleProof

    def to_bytes(self) -> bytes:
        return (
            canonical_int(self.index, 8) +
            canonical_bytes(self.c) +
            self.tok.to_bytes() +
            self.merkle_proof.to_bytes()
        )
