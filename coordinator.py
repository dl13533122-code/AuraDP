"""
AuraLDP Coordinator/Combiner Implementation
Orchestrates the protocol flow, collects results, and produces final output
Supports TNO threshold decryption
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from models import (
    SignedBatchStatement, SeedCert, SeedCommit, SeedReveal,
    PASSApproval, GlobalStatement, FinalCert, DecryptShare, H
)
from crypto import (
    verify_signature, load_public_key,
    PaillierPublicKeyBase, PaillierPrivateKeyBase,
    ThresholdPaillierSetup, ThresholdPaillierManager, PartialDecryption
)
from server import AggregatorServer
from auditor import Auditor


class RoundPhase(Enum):
    """Phases of a round"""
    SUBMISSION = "submission"
    BATCH_FINALIZE = "batch_finalize"
    SEED_COMMIT = "seed_commit"
    SEED_REVEAL = "seed_reveal"
    AUDIT = "audit"
    FINALITY = "finality"
    DECRYPT = "decrypt"
    COMPLETE = "complete"


@dataclass
class EquivocationEvidence:
    """Evidence of server equivocation"""
    server_id: int
    stmt_1: SignedBatchStatement
    stmt_2: SignedBatchStatement


@dataclass
class RoundTranscript:
    """Complete transcript of a round for verification"""
    rid: bytes
    seed_cert: SeedCert
    batch_statements: Dict[int, SignedBatchStatement]
    pass_approvals: Dict[int, List[PASSApproval]]
    final_cert: FinalCert
    decrypt_shares: List[DecryptShare]
    C_glob: bytes
    Y_glob: int
    n_glob: int
    I_acc: List[int]
    equivocations: List[EquivocationEvidence]


@dataclass
class CoordinatorRoundState:
    """Coordinator state for a single round"""
    rid: bytes
    phase: RoundPhase = RoundPhase.SUBMISSION

    # Batch statements
    statements: Dict[int, SignedBatchStatement] = field(default_factory=dict)
    equivocations: List[EquivocationEvidence] = field(default_factory=list)

    # Seed commit-reveal
    commits: Dict[int, SeedCommit] = field(default_factory=dict)
    reveals: Dict[int, SeedReveal] = field(default_factory=dict)
    seed_cert: Optional[SeedCert] = None

    # PASS approvals
    pass_approvals: Dict[int, List[PASSApproval]] = field(default_factory=dict)
    I_acc: Set[int] = field(default_factory=set)

    # Final cert
    global_stmt: Optional[GlobalStatement] = None
    finality_sigs: Dict[int, bytes] = field(default_factory=dict)
    final_cert: Optional[FinalCert] = None

    # Decryption (optional legacy path)
    decrypt_shares: List[DecryptShare] = field(default_factory=list)
    Y_glob: Optional[int] = None


class Coordinator:
    """
    Protocol coordinator/combiner.
    Orchestrates the full protocol flow for each round.
    """

    def __init__(
        self,
        paillier_pk: PaillierPublicKeyBase,
        all_server_public_keys: Dict[int, bytes],
        auditor_public_keys: Dict[int, bytes],
        threshold_setup: Optional[ThresholdPaillierSetup] = None,
        threshold_audit: int = 1,
        threshold_finality: int = 2,
        threshold_decrypt: int = 2,
    ):
        self.paillier_pk = paillier_pk
        self.server_pks = {
            sid: load_public_key(pk) for sid, pk in all_server_public_keys.items()
        }
        self.auditor_pks = {
            aid: load_public_key(pk) for aid, pk in auditor_public_keys.items()
        }
        self.threshold_setup = threshold_setup
        self.threshold_audit = threshold_audit
        self.threshold_finality = threshold_finality
        self.threshold_decrypt = threshold_decrypt

        if threshold_setup:
            self.threshold_manager = ThresholdPaillierManager(threshold_setup)
        else:
            self.threshold_manager = None

        self.rounds: Dict[bytes, CoordinatorRoundState] = {}

    def _get_round(self, rid: bytes) -> CoordinatorRoundState:
        if rid not in self.rounds:
            self.rounds[rid] = CoordinatorRoundState(rid=rid)
        return self.rounds[rid]

    # ========================================================================
    # Phase 1: Collect Batch Statements
    # ========================================================================

    def receive_batch_statement(self, signed_stmt: SignedBatchStatement) -> bool:
        """Receive and validate a batch statement"""
        stmt = signed_stmt.stmt
        rid = stmt.rid
        server_id = stmt.server_id
        round_state = self._get_round(rid)

        server_pk = self.server_pks.get(server_id)
        if server_pk is None:
            return False

        if not verify_signature(server_pk, stmt.to_bytes(), signed_stmt.sig_server):
            return False

        # Check for equivocation
        if server_id in round_state.statements:
            existing = round_state.statements[server_id]
            if existing.stmt.to_bytes() != stmt.to_bytes():
                round_state.equivocations.append(
                    EquivocationEvidence(
                        server_id=server_id,
                        stmt_1=existing,
                        stmt_2=signed_stmt
                    )
                )
                return False

        round_state.statements[server_id] = signed_stmt
        return True

    # ========================================================================
    # Phase 2: Seed Commit-Reveal
    # ========================================================================

    def receive_seed_commit(self, commit: SeedCommit) -> bool:
        """Receive a seed commitment"""
        round_state = self._get_round(commit.rid)
        round_state.commits[commit.server_id] = commit
        return True

    def receive_seed_reveal(self, reveal: SeedReveal) -> bool:
        """Receive and verify a seed reveal"""
        round_state = self._get_round(reveal.rid)

        expected_commit = round_state.commits.get(reveal.server_id)
        if expected_commit is None:
            return False

        actual_commit = reveal.compute_commit()
        if actual_commit != expected_commit.commit:
            return False

        round_state.reveals[reveal.server_id] = reveal
        return True

    def compute_seed_cert(
        self,
        rid: bytes,
        server_signatures: Dict[int, bytes]
    ) -> Optional[SeedCert]:
        """Compute the combined seed and create SeedCert"""
        round_state = self._get_round(rid)

        if not round_state.reveals:
            return None

        # Combine all revealed random values (XOR)
        combined_seed = bytes(32)
        for reveal in round_state.reveals.values():
            combined_seed = bytes(a ^ b for a, b in zip(combined_seed, reveal.random_value))

        h_seed = H(rid, combined_seed, domain="AuraLDP-seed")

        valid_sigs: Dict[int, bytes] = {}
        seed_cert_msg = H(rid, h_seed, domain="AuraLDP-seed-cert")

        for server_id, sig in server_signatures.items():
            server_pk = self.server_pks.get(server_id)
            if server_pk and verify_signature(server_pk, seed_cert_msg, sig):
                valid_sigs[server_id] = sig

        seed_cert = SeedCert(
            rid=rid,
            seed_rid=combined_seed,
            h_seed=h_seed,
            sigs=valid_sigs
        )

        round_state.seed_cert = seed_cert
        return seed_cert

    # ========================================================================
    # Phase 3: Collect PASS Approvals
    # ========================================================================

    def receive_pass_approval(self, approval: PASSApproval) -> bool:
        """Receive and validate a PASS approval"""
        rid = approval.rid
        round_state = self._get_round(rid)
        server_id = approval.audited_server_id

        msg = approval.compute_message()
        valid = False

        for auditor_pk in self.auditor_pks.values():
            if verify_signature(auditor_pk, msg, approval.sig_auditor):
                valid = True
                break

        if not valid:
            return False

        if server_id not in round_state.pass_approvals:
            round_state.pass_approvals[server_id] = []

        round_state.pass_approvals[server_id].append(approval)

        if len(round_state.pass_approvals[server_id]) >= self.threshold_audit:
            round_state.I_acc.add(server_id)

        return True

    # ========================================================================
    # Phase 4: Compute Global Statement and Collect Finality Signatures
    # ========================================================================

    def compute_global_statement(self, rid: bytes) -> Optional[GlobalStatement]:
        """Compute the global statement from accepted batches"""
        round_state = self._get_round(rid)

        if not round_state.I_acc:
            return None

        if round_state.seed_cert is None:
            return None

        # Compute C_glob = product (homomorphic sum) of all C_i
        first_server_id = sorted(round_state.I_acc)[0]
        first_stmt = round_state.statements[first_server_id].stmt
        C_glob = self.paillier_pk.deserialize_ciphertext(first_stmt.C_i)
        n_glob = first_stmt.n_i
        batch_hashes = {first_server_id: first_stmt.compute_hash()}

        for server_id in sorted(round_state.I_acc)[1:]:
            stmt = round_state.statements[server_id].stmt
            C_i = self.paillier_pk.deserialize_ciphertext(stmt.C_i)
            C_glob = self.paillier_pk.add_ciphertexts(C_glob, C_i)
            n_glob += stmt.n_i
            batch_hashes[server_id] = stmt.compute_hash()

        C_glob_bytes = self.paillier_pk.serialize_ciphertext(C_glob)

        global_stmt = GlobalStatement(
            rid=rid,
            h_seed=round_state.seed_cert.h_seed,
            I_acc=sorted(round_state.I_acc),
            batch_hashes=batch_hashes,
            C_glob=C_glob_bytes,
            n_glob=n_glob
        )

        round_state.global_stmt = global_stmt
        return global_stmt

    def receive_finality_signature(
        self,
        rid: bytes,
        server_id: int,
        signature: bytes
    ) -> bool:
        """Receive a finality signature"""
        round_state = self._get_round(rid)

        if round_state.global_stmt is None:
            return False

        h_glob = round_state.global_stmt.compute_hash()
        msg = FinalCert.compute_finality_message(rid, h_glob)

        server_pk = self.server_pks.get(server_id)
        if server_pk is None:
            return False

        if not verify_signature(server_pk, msg, signature):
            return False

        round_state.finality_sigs[server_id] = signature
        return True

    def create_final_cert(self, rid: bytes) -> Optional[FinalCert]:
        """Create final certificate"""
        round_state = self._get_round(rid)

        if round_state.global_stmt is None:
            return None

        if len(round_state.finality_sigs) < self.threshold_finality:
            return None

        h_glob = round_state.global_stmt.compute_hash()

        final_cert = FinalCert(
            glob_stmt=round_state.global_stmt,
            h_glob=h_glob,
            fin_sigs=round_state.finality_sigs.copy()
        )

        round_state.final_cert = final_cert
        return final_cert

    # ========================================================================
    # Phase 5: (Legacy) Collect Decrypt Shares and Combine
    # ========================================================================

    def receive_decrypt_share(self, share: DecryptShare) -> bool:
        """
        Receive a decryption share.

        NOTE:
        - In TNO distributed_keygen mode, decryption is interactive and we do NOT
          use per-server shares in this demo.
        - This method is kept for compatibility with older / simulated paths.
        """
        round_state = self._get_round(share.rid)

        if round_state.final_cert is None:
            return False

        if share.h_glob != round_state.final_cert.h_glob:
            return False

        round_state.decrypt_shares.append(share)
        return True

    def combine_decrypt_shares(
        self,
        rid: bytes,
        private_key: Optional[PaillierPrivateKeyBase] = None
    ) -> Optional[int]:
        """
        Decrypt the global aggregate ciphertext.

        Preferred path:
        - If `private_key` is provided, use it. In distributed mode this can be a
          DistributedPrivateKey that internally runs the interactive threshold decrypt.

        Legacy path (kept for compatibility):
        - Attempt to combine collected `DecryptShare` objects via ThresholdPaillierManager.
        """
        from crypto import TNO_AVAILABLE

        round_state = self._get_round(rid)

        if round_state.global_stmt is None:
            return None

        # Deserialize the aggregate ciphertext
        C_glob = self.paillier_pk.deserialize_ciphertext(round_state.global_stmt.C_glob)

        # Preferred: decrypt via provided private_key interface
        if private_key is not None:
            Y_glob = private_key.decrypt(C_glob)
            round_state.Y_glob = Y_glob
            return Y_glob

        # Legacy: try combining collected shares (may be unused / unsupported)
        if (
            TNO_AVAILABLE and
            self.threshold_manager and
            len(round_state.decrypt_shares) >= self.threshold_decrypt
        ):
            partials: List[PartialDecryption] = []
            for share in round_state.decrypt_shares:
                partial_value = int.from_bytes(share.partial_decryption, "big")
                partials.append(
                    PartialDecryption(
                        server_id=share.server_id,
                        value=partial_value,
                        proof=share.proof
                    )
                )

            try:
                Y_glob = self.threshold_manager.combine_partial_decryptions(partials, C_glob)
                if Y_glob != 0:
                    round_state.Y_glob = Y_glob
                    return Y_glob
            except Exception:
                pass

        return None

    # ========================================================================
    # Generate Complete Transcript
    # ========================================================================

    def generate_transcript(self, rid: bytes) -> Optional[RoundTranscript]:
        """Generate complete round transcript"""
        round_state = self._get_round(rid)

        if round_state.final_cert is None:
            return None

        return RoundTranscript(
            rid=rid,
            seed_cert=round_state.seed_cert,
            batch_statements=round_state.statements.copy(),
            pass_approvals=round_state.pass_approvals.copy(),
            final_cert=round_state.final_cert,
            decrypt_shares=round_state.decrypt_shares.copy(),
            C_glob=round_state.global_stmt.C_glob,
            Y_glob=round_state.Y_glob if round_state.Y_glob is not None else 0,
            n_glob=round_state.global_stmt.n_glob,
            I_acc=list(round_state.I_acc),
            equivocations=round_state.equivocations.copy()
        )


# ============================================================================
# Protocol Orchestrator
# ============================================================================

class ProtocolOrchestrator:
    """
    High-level orchestrator that runs the complete protocol.
    """

    def __init__(
        self,
        servers: List[AggregatorServer],
        auditors: List[Auditor],
        coordinator: Coordinator,
        paillier_private_key: Optional[PaillierPrivateKeyBase] = None
    ):
        self.servers = {s.server_id: s for s in servers}
        self.auditors = auditors
        self.coordinator = coordinator
        self.paillier_private_key = paillier_private_key

    def run_round(self, rid: bytes) -> Optional[RoundTranscript]:
        """Run a complete protocol round"""
        print(f"=== Starting round {rid.hex()[:8]}... ===")

        # Phase 1: Finalize batches
        print("\n[Phase 1] Finalizing batches...")
        for server in self.servers.values():
            signed_stmt = server.finalize_batch(rid)
            if signed_stmt:
                self.coordinator.receive_batch_statement(signed_stmt)
                print(f"  Server {server.server_id}: {signed_stmt.stmt.n_i} records")

        # Phase 2: Seed commit-reveal
        print("\n[Phase 2] Seed commit-reveal...")
        commits: Dict[int, SeedCommit] = {}
        reveals: Dict[int, SeedReveal] = {}

        for server in self.servers.values():
            commit = server.generate_seed_commit(rid)
            commits[server.server_id] = commit
            self.coordinator.receive_seed_commit(commit)

        for server in self.servers.values():
            for other_id, commit in commits.items():
                if other_id != server.server_id:
                    server.receive_seed_commit(commit)

        for server in self.servers.values():
            reveal = server.get_seed_reveal(rid)
            if reveal:
                reveals[server.server_id] = reveal
                self.coordinator.receive_seed_reveal(reveal)

        for server in self.servers.values():
            for other_id, reveal in reveals.items():
                if other_id != server.server_id:
                    server.receive_seed_reveal(reveal)

        seed_sigs: Dict[int, bytes] = {}
        combined_seed = bytes(32)
        for reveal in reveals.values():
            combined_seed = bytes(a ^ b for a, b in zip(combined_seed, reveal.random_value))

        h_seed = H(rid, combined_seed, domain="AuraLDP-seed")

        for server in self.servers.values():
            sig = server.sign_seed_cert(rid, h_seed)
            seed_sigs[server.server_id] = sig

        seed_cert = self.coordinator.compute_seed_cert(rid, seed_sigs)
        if seed_cert is None:
            print("  Failed to create seed cert")
            return None

        print(f"  Seed: {seed_cert.seed_rid.hex()[:16]}...")

        for server in self.servers.values():
            server.store_seed_cert(seed_cert)

        # Phase 3: Audit
        print("\n[Phase 3] Auditing...")
        round_state = self.coordinator._get_round(rid)

        for auditor in self.auditors:
            for server_id, signed_stmt in round_state.statements.items():
                server = self.servers[server_id]
                result = auditor.audit_server(server, signed_stmt, seed_cert)

                if result.success and result.pass_approval:
                    self.coordinator.receive_pass_approval(result.pass_approval)
                    print(f"  Auditor {auditor.auditor_id} -> Server {server_id}: PASS")
                else:
                    print(f"  Auditor {auditor.auditor_id} -> Server {server_id}: FAIL - {result.error_message}")

        # Phase 4: Finality
        print("\n[Phase 4] Finality signatures...")
        global_stmt = self.coordinator.compute_global_statement(rid)
        if global_stmt is None:
            print("  No accepted servers")
            return None

        h_glob = global_stmt.compute_hash()
        print(f"  Global: n={global_stmt.n_glob}, I_acc={global_stmt.I_acc}")

        for server in self.servers.values():
            fin_sig = server.sign_finality(rid, h_glob)
            self.coordinator.receive_finality_signature(rid, server.server_id, fin_sig)

        final_cert = self.coordinator.create_final_cert(rid)
        if final_cert is None:
            print("  Failed to create final cert")
            return None

        for server in self.servers.values():
            server.store_final_cert(final_cert)

        # Phase 5: Decryption
        print("\n[Phase 5] Decryption...")

        # NOTE: In TNO distributed_keygen mode, decryption is interactive.
        # We do NOT collect per-server DecryptShare objects here.
        Y_glob = self.coordinator.combine_decrypt_shares(
            rid, private_key=self.paillier_private_key
        )

        if Y_glob is not None:
            print(f"  Result: Y_glob = {Y_glob}")
        else:
            print("  Decryption incomplete")

        transcript = self.coordinator.generate_transcript(rid)
        print(f"\n=== Round {rid.hex()[:8]} complete ===")

        return transcript