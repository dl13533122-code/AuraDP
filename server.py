"""
AuraLDP Aggregator Server Implementation
Handles user submissions, batch finalization, audit responses, and protocol participation
Supports TNO Paillier integration
"""

import threading
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

from models import (
    Record, Token, BatchStatement, SignedBatchStatement,
    SeedCommit, SeedReveal, SeedCert, PASSApproval,
    GlobalStatement, FinalCert, DecryptShare,
    MerkleProof, AuditOpenItem, H, canonical_int
)
from merkle import MerkleTreeCache
from crypto import (
    KeyPair,
    PaillierPublicKeyBase, PaillierPrivateKeyBase,
    ThresholdPaillierSetup, ThresholdPaillierManager,
    generate_random_bytes,
    # RSA blind verify helpers
    rsa_verify, fixed_len_bytes_to_int,
    RSABlindKeyPair, generate_rsa_blind_keypair, rsa_blind_sign, int_to_fixed_len_bytes
)


class SubmitError(Enum):
    OK = "ok"
    DUPLICATE_REQ_ID = "duplicate_req_id"
    DUPLICATE_TAG = "duplicate_tag"
    BAD_TOKEN = "bad_token"
    BAD_BINDING = "bad_binding"
    BAD_CIPHERTEXT = "bad_ciphertext"
    ROUND_CLOSED = "round_closed"
    WRONG_SERVER = "wrong_server"


@dataclass
class SubmitResult:
    """Result of a submit operation"""
    error: SubmitError
    index: Optional[int] = None


@dataclass
class AcceptedRecord:
    """Stored record with index"""
    index: int
    tag: bytes
    c: bytes           # Serialized ciphertext
    c_obj: Any         # Ciphertext object (for aggregation)
    h: bytes
    tok: Token
    leaf_hash: bytes


@dataclass
class RoundState:
    """State for a single round on this server"""
    rid: bytes
    server_id: int

    # Deduplication sets
    seen_req_ids: Set[bytes] = field(default_factory=set)
    seen_tags: Set[bytes] = field(default_factory=set)

    # Accepted records
    accepted_records: List[AcceptedRecord] = field(default_factory=list)

    # Merkle tree cache
    merkle_cache: MerkleTreeCache = field(default_factory=MerkleTreeCache)

    # Batch statement
    stmt: Optional[BatchStatement] = None
    signed_stmt: Optional[SignedBatchStatement] = None

    # Seed commit-reveal
    my_commit: Optional[SeedCommit] = None
    my_reveal: Optional[SeedReveal] = None
    received_commits: Dict[int, SeedCommit] = field(default_factory=dict)
    received_reveals: Dict[int, SeedReveal] = field(default_factory=dict)
    seed_cert: Optional[SeedCert] = None

    # Final cert
    final_cert: Optional[FinalCert] = None

    # State flags
    is_accepting_submissions: bool = True
    is_finalized: bool = False

    # Lock for thread safety
    _lock: threading.Lock = field(default_factory=threading.Lock)


class AggregatorServer:
    """
    Aggregator Server (S_i) implementation.
    Handles user submissions, batch processing, and protocol participation.
    """

    def __init__(
        self,
        server_id: int,
        keypair: KeyPair,
        issuer_rsa_public_key: Tuple[int, int],  # (n, e)
        paillier_pk: PaillierPublicKeyBase,
        all_server_public_keys: Dict[int, bytes],
        threshold_setup: Optional[ThresholdPaillierSetup] = None,
        threshold_decrypt: int = 2,
        threshold_finality: int = 2,
    ):
        self.server_id = server_id
        self.keypair = keypair

        self.issuer_rsa_n, self.issuer_rsa_e = issuer_rsa_public_key

        self.paillier_pk = paillier_pk
        # NOTE: server public keys are Ed25519 raw bytes; the coordinator/auditor uses Ed25519 verify.
        # Here we keep them as bytes only if needed elsewhere; no load_public_key in this file now.
        self.all_server_pks_bytes = dict(all_server_public_keys)

        self.threshold_setup = threshold_setup
        self.threshold_decrypt = threshold_decrypt
        self.threshold_finality = threshold_finality

        if threshold_setup:
            self.threshold_manager = ThresholdPaillierManager(threshold_setup)
        else:
            self.threshold_manager = None

        self.rounds: Dict[bytes, RoundState] = {}
        self._global_lock = threading.Lock()

    def _get_or_create_round(self, rid: bytes) -> RoundState:
        """Get or create round state"""
        with self._global_lock:
            if rid not in self.rounds:
                self.rounds[rid] = RoundState(rid=rid, server_id=self.server_id)
            return self.rounds[rid]

    # ========================================================================
    # API: Submit
    # ========================================================================

    def submit(self, record: Record) -> SubmitResult:
        """
        Process a user submission.
        POST /v1/submit
        """
        round_state = self._get_or_create_round(record.rid)

        with round_state._lock:
            # 1. Check round is accepting submissions
            if not round_state.is_accepting_submissions:
                return SubmitResult(error=SubmitError.ROUND_CLOSED)

            # 2. Check server_id matches
            if record.server_id != self.server_id:
                return SubmitResult(error=SubmitError.WRONG_SERVER)

            # 3. req_id deduplication
            if record.req_id in round_state.seen_req_ids:
                return SubmitResult(error=SubmitError.DUPLICATE_REQ_ID)

            # 4. Verify token signature (RSA blind signature unblinded by user)
            token_msg = self._compute_token_message(record)
            sig_int = fixed_len_bytes_to_int(record.tok.sig)
            if not rsa_verify(token_msg, sig_int, self.issuer_rsa_n, self.issuer_rsa_e):
                return SubmitResult(error=SubmitError.BAD_TOKEN)

            # 5. Verify binding hash
            expected_h = record.compute_binding_hash()
            if record.tok.h != expected_h:
                return SubmitResult(error=SubmitError.BAD_BINDING)

            # 6. Derive tag and check uniqueness
            tag = record.compute_tag()
            if tag in round_state.seen_tags:
                return SubmitResult(error=SubmitError.DUPLICATE_TAG)

            # 7. Deserialize and validate ciphertext
            try:
                c_obj = self.paillier_pk.deserialize_ciphertext(record.c)
                if not self.paillier_pk.validate_ciphertext(c_obj):
                    return SubmitResult(error=SubmitError.BAD_CIPHERTEXT)
            except Exception:
                return SubmitResult(error=SubmitError.BAD_CIPHERTEXT)

            # 8. All checks passed - commit atomically
            round_state.seen_req_ids.add(record.req_id)
            round_state.seen_tags.add(tag)

            leaf_hash = record.compute_leaf_hash()

            index = len(round_state.accepted_records)
            accepted = AcceptedRecord(
                index=index,
                tag=tag,
                c=record.c,
                c_obj=c_obj,
                h=record.tok.h,
                tok=record.tok,
                leaf_hash=leaf_hash
            )
            round_state.accepted_records.append(accepted)

            round_state.merkle_cache.append(leaf_hash)

            return SubmitResult(error=SubmitError.OK, index=index)

    def _compute_token_message(self, record: Record) -> bytes:
        """Compute the message that should have been signed by issuer"""
        return H(
            record.rid,
            canonical_int(record.server_id),
            record.tok.m,
            record.tok.h,
            domain="AuraLDP-token"
        )

    # ========================================================================
    # API: Finalize Batch
    # ========================================================================

    def finalize_batch(self, rid: bytes) -> Optional[SignedBatchStatement]:
        """
        Finalize batch for a round.
        POST /v1/round/{rid}/finalize-batch
        """
        round_state = self._get_or_create_round(rid)

        with round_state._lock:
            if round_state.is_finalized:
                return round_state.signed_stmt

            round_state.is_accepting_submissions = False

            if not round_state.accepted_records:
                round_state.is_finalized = True
                return None

            root = round_state.merkle_cache.finalize()

            C_i = round_state.accepted_records[0].c_obj
            for rec in round_state.accepted_records[1:]:
                C_i = self.paillier_pk.add_ciphertexts(C_i, rec.c_obj)

            C_i_bytes = self.paillier_pk.serialize_ciphertext(C_i)

            stmt = BatchStatement(
                rid=rid,
                server_id=self.server_id,
                n_i=len(round_state.accepted_records),
                root_i=root,
                C_i=C_i_bytes
            )

            sig = self.keypair.sign(stmt.to_bytes())
            signed_stmt = SignedBatchStatement(stmt=stmt, sig_server=sig)

            round_state.stmt = stmt
            round_state.signed_stmt = signed_stmt
            round_state.is_finalized = True

            return signed_stmt

    # ========================================================================
    # API: Audit Open
    # ========================================================================

    def audit_open(self, rid: bytes, indices: List[int]) -> List[AuditOpenItem]:
        """
        Open records for audit.
        POST /v1/audit/open
        """
        round_state = self._get_or_create_round(rid)

        with round_state._lock:
            if not round_state.is_finalized:
                raise RuntimeError("Round not finalized")

            items = []
            for idx in indices:
                if idx < 0 or idx >= len(round_state.accepted_records):
                    raise ValueError(f"Index {idx} out of range")

                rec = round_state.accepted_records[idx]
                proof = round_state.merkle_cache.get_proof(idx)

                items.append(AuditOpenItem(index=idx, c=rec.c, tok=rec.tok, merkle_proof=proof))

            return items

    # ========================================================================
    # API: Seed Commit-Reveal
    # ========================================================================

    def generate_seed_commit(self, rid: bytes) -> SeedCommit:
        """Generate and store seed commitment"""
        round_state = self._get_or_create_round(rid)

        with round_state._lock:
            random_value = generate_random_bytes(32)
            nonce = generate_random_bytes(16)
            commit = H(random_value, nonce, domain="AuraLDP-commit")

            seed_commit = SeedCommit(rid=rid, server_id=self.server_id, commit=commit)

            round_state.my_commit = seed_commit
            round_state.my_reveal = SeedReveal(
                rid=rid,
                server_id=self.server_id,
                random_value=random_value,
                nonce=nonce
            )

            return seed_commit

    def receive_seed_commit(self, commit: SeedCommit):
        round_state = self._get_or_create_round(commit.rid)
        with round_state._lock:
            round_state.received_commits[commit.server_id] = commit

    def get_seed_reveal(self, rid: bytes) -> Optional[SeedReveal]:
        round_state = self._get_or_create_round(rid)
        with round_state._lock:
            return round_state.my_reveal

    def receive_seed_reveal(self, reveal: SeedReveal) -> bool:
        round_state = self._get_or_create_round(reveal.rid)

        with round_state._lock:
            expected_commit = round_state.received_commits.get(reveal.server_id)
            if expected_commit is None:
                return False

            if reveal.compute_commit() != expected_commit.commit:
                return False

            round_state.received_reveals[reveal.server_id] = reveal
            return True

    def compute_combined_seed(self, rid: bytes) -> Optional[bytes]:
        round_state = self._get_or_create_round(rid)

        with round_state._lock:
            if not round_state.received_reveals:
                return None

            combined = bytes(32)
            for reveal in round_state.received_reveals.values():
                combined = bytes(a ^ b for a, b in zip(combined, reveal.random_value))
            return combined

    def sign_seed_cert(self, rid: bytes, h_seed: bytes) -> bytes:
        msg = H(rid, h_seed, domain="AuraLDP-seed-cert")
        return self.keypair.sign(msg)

    def store_seed_cert(self, seed_cert: SeedCert):
        round_state = self._get_or_create_round(seed_cert.rid)
        with round_state._lock:
            round_state.seed_cert = seed_cert

    # ========================================================================
    # API: Finality Signature
    # ========================================================================

    def sign_finality(self, rid: bytes, h_glob: bytes) -> bytes:
        msg = FinalCert.compute_finality_message(rid, h_glob)
        return self.keypair.sign(msg)

    def store_final_cert(self, final_cert: FinalCert):
        round_state = self._get_or_create_round(final_cert.glob_stmt.rid)
        with round_state._lock:
            round_state.final_cert = final_cert

    # ========================================================================
    # API: Decrypt Share (TNO threshold)
    # ========================================================================

    def generate_decrypt_share(self, rid: bytes, C_glob: bytes, final_cert: FinalCert) -> DecryptShare:
        h_glob = final_cert.h_glob

        if self.threshold_manager:
            c_obj = self.paillier_pk.deserialize_ciphertext(C_glob)
            partial = self.threshold_manager.generate_partial_decryption(self.server_id, c_obj)
            partial_bytes = partial.value.to_bytes((partial.value.bit_length() + 7) // 8 or 1, 'big')
            proof = partial.proof
        else:
            partial_bytes = generate_random_bytes(64)
            proof = b""

        return DecryptShare(
            rid=rid,
            h_glob=h_glob,
            server_id=self.server_id,
            partial_decryption=partial_bytes,
            proof=proof
        )

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def get_batch_statement(self, rid: bytes) -> Optional[SignedBatchStatement]:
        if rid not in self.rounds:
            return None
        return self.rounds[rid].signed_stmt

    def get_record_count(self, rid: bytes) -> int:
        if rid not in self.rounds:
            return 0
        return len(self.rounds[rid].accepted_records)

    def close_round(self, rid: bytes):
        round_state = self._get_or_create_round(rid)
        with round_state._lock:
            round_state.is_accepting_submissions = False


# ============================================================================
# Issuer Service (RSA blind signatures)
# ============================================================================

class Issuer:
    """
    Token issuer service using RSA-FDH blind signatures.

    - Client computes (m,h) and token_msg = H(rid, server_id, m, h, domain="AuraLDP-token")
    - Client blinds token_msg and sends blinded to issuer.
    - Issuer returns blind signature.
    - Client unblinds and uses it as Token.sig.
    """

    def __init__(self, rsa_keypair: Optional[RSABlindKeyPair] = None, rsa_bits: int = 2048):
        self.rsa = rsa_keypair or generate_rsa_blind_keypair(bits=rsa_bits)

    def public_key(self) -> Tuple[int, int]:
        """Return (n,e)"""
        return (self.rsa.n, self.rsa.e)

    def blind_sign(self, blinded_bytes: bytes) -> bytes:
        """
        blinded_bytes: big-endian int in bytes (must be < n)
        returns: blind signature as fixed-length bytes (len = modulus size)
        """
        blinded_int = int.from_bytes(blinded_bytes, "big")
        sig_int = rsa_blind_sign(blinded_int, self.rsa.d, self.rsa.n)
        return int_to_fixed_len_bytes(sig_int, self.rsa.modulus_bytes_len)

    def modulus_bytes_len(self) -> int:
        return self.rsa.modulus_bytes_len