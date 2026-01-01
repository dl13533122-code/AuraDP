"""
AuraLDP Auditor Implementation
Handles sampling, verification, and PASS approval generation
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from models import (
    SignedBatchStatement, SeedCert, PASSApproval, AuditOpenItem,
    H, canonical_int
)
from merkle import verify_merkle_proof
from crypto import (
    KeyPair, verify_signature, load_public_key,
    deterministic_sample,
    rsa_verify, fixed_len_bytes_to_int
)
from server import AggregatorServer


@dataclass
class AuditResult:
    """Result of auditing a single server's batch"""
    server_id: int
    success: bool
    pass_approval: Optional[PASSApproval] = None
    failed_indices: Optional[List[int]] = None
    error_message: Optional[str] = None


class Auditor:
    """
    Auditor implementation.
    Can be a separate service or servers auditing each other.
    """

    def __init__(
        self,
        auditor_id: int,
        keypair: KeyPair,
        issuer_rsa_public_key: Tuple[int, int],   # (n,e)
        all_server_public_keys: Dict[int, bytes],
        sample_count: int = 10,
    ):
        self.auditor_id = auditor_id
        self.keypair = keypair
        self.issuer_rsa_n, self.issuer_rsa_e = issuer_rsa_public_key

        self.all_server_pks = {
            sid: load_public_key(pk_bytes)
            for sid, pk_bytes in all_server_public_keys.items()
        }
        self.sample_count = sample_count

    def audit_server(
        self,
        server: AggregatorServer,
        signed_stmt: SignedBatchStatement,
        seed_cert: SeedCert,
    ) -> AuditResult:
        stmt = signed_stmt.stmt
        rid = stmt.rid
        server_id = stmt.server_id
        n_i = stmt.n_i

        # 1. Verify server signature (Ed25519)
        server_pk = self.all_server_pks.get(server_id)
        if server_pk is None:
            return AuditResult(server_id=server_id, success=False, error_message=f"Unknown server ID: {server_id}")

        if not verify_signature(server_pk, stmt.to_bytes(), signed_stmt.sig_server):
            return AuditResult(server_id=server_id, success=False, error_message="Invalid server signature on batch statement")

        # 2. Handle empty batch
        if n_i == 0:
            pass_approval = self._create_pass_approval(stmt, seed_cert.h_seed)
            return AuditResult(server_id=server_id, success=True, pass_approval=pass_approval)

        # 3. Compute sample indices
        sample_indices = deterministic_sample(
            seed=seed_cert.seed_rid,
            rid=rid,
            server_id=server_id,
            n_records=n_i,
            sample_count=min(self.sample_count, n_i)
        )

        # 4. Request opened records
        try:
            opened_items = server.audit_open(rid, sample_indices)
        except Exception as e:
            return AuditResult(server_id=server_id, success=False, error_message=f"Failed to open records: {e}")

        # 5. Verify each opened record
        failed_indices = []
        for item in opened_items:
            if not self._verify_opened_record(item, stmt, rid, server_id):
                failed_indices.append(item.index)

        if failed_indices:
            return AuditResult(
                server_id=server_id,
                success=False,
                failed_indices=failed_indices,
                error_message=f"Verification failed for indices: {failed_indices}"
            )

        # 6. All checks passed
        pass_approval = self._create_pass_approval(stmt, seed_cert.h_seed)
        return AuditResult(server_id=server_id, success=True, pass_approval=pass_approval)

    def _verify_opened_record(self, item: AuditOpenItem, stmt, rid: bytes, server_id: int) -> bool:
        """
        Verify an opened record.

        Checks:
        1. Token signature is valid (RSA verify on token_msg)
        2. Binding hash h == H("AuraLDP-bind" || rid || c)
        3. Leaf hash matches
        4. Merkle proof verifies against root_i
        """
        tok = item.tok
        c = item.c

        # 1. Verify token signature (RSA)
        token_msg = H(
            rid,
            canonical_int(server_id),
            tok.m,
            tok.h,
            domain="AuraLDP-token"
        )

        sig_int = fixed_len_bytes_to_int(tok.sig)
        if not rsa_verify(token_msg, sig_int, self.issuer_rsa_n, self.issuer_rsa_e):
            return False

        # 2. Verify binding hash
        expected_h = H(rid, c, domain="AuraLDP-bind")
        if tok.h != expected_h:
            return False

        # 3. Compute expected leaf hash
        tag = H(rid, tok.m, domain="AuraLDP-tag")
        expected_leaf = H(rid, tag, c, tok.h, domain="AuraLDP-leaf")
        if item.merkle_proof.leaf_hash != expected_leaf:
            return False

        # 4. Verify Merkle proof
        if not verify_merkle_proof(item.merkle_proof, stmt.root_i):
            return False

        return True

    def _create_pass_approval(self, stmt, h_seed: bytes) -> PASSApproval:
        pass_approval = PASSApproval(
            rid=stmt.rid,
            audited_server_id=stmt.server_id,
            n_i=stmt.n_i,
            root_i=stmt.root_i,
            C_i=stmt.C_i,
            h_seed=h_seed,
            sig_auditor=b""
        )

        msg = pass_approval.compute_message()
        sig = self.keypair.sign(msg)
        pass_approval.sig_auditor = sig
        return pass_approval