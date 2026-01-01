"""
AuraLDP Demo Script (Peer Auditing Version)
- Auditors are other servers (N-1 peer auditing): for server j, auditors = all servers i != j
- Unified threshold t controls:
  * Paillier threshold in DKG (t-of-n)
  * Audit threshold (need t PASS approvals from other servers)
  * Finality threshold (need t finality signatures)
  * (Legacy) decrypt threshold (kept consistent)
- Adds CLI args for epsilon/scale, num-servers, threshold t, etc.

UPDATED:
- User generates m (nonce) locally (paper-aligned)
- Issuer issues token using RSA-FDH blind signatures:
  Blind(token_msg) -> issuer.blind_sign(blinded) -> Unblind(blind_sig)
"""

import random
import struct
import argparse
import numpy as np
from Laplacenvp import laplace
from typing import Dict

from models import Record, Token, H, canonical_int
from crypto import (
    generate_keypair,
    generate_threshold_setup,
    generate_req_id,
    generate_random_bytes,
    rsa_blind, rsa_unblind,
    int_to_fixed_len_bytes, fixed_len_bytes_to_int,
)
from server import AggregatorServer, Issuer, SubmitError
from auditor import Auditor
from coordinator import Coordinator, ProtocolOrchestrator


# =============================================================================
# Setup
# =============================================================================

def create_test_setup(
    num_servers: int = 3,
    paillier_bits: int = 512,
    use_distributed: bool = False,
    threshold: int = 2,          # unified threshold t
    sample_count: int = 5,        # audit sample per auditor per server
) -> Dict:
    """Create servers + peer-auditors + coordinator."""
    print("=" * 60)
    print("AuraLDP Protocol Demo (Peer Auditing) - Blind Token Issuance")
    print("=" * 60)

    mode_str = "distributed (TNO DKG)" if use_distributed else "single-party / fallback"
    print(f"\n[Setup] Generating threshold Paillier setup ({mode_str})...")
    threshold_setup, paillier_sk = generate_threshold_setup(
        bits=paillier_bits,
        threshold=threshold,
        total_servers=num_servers,
        use_distributed=use_distributed
    )
    paillier_pk = threshold_setup.public_key
    print(f"  N bit length: {paillier_pk.get_n().bit_length()}")
    if use_distributed:
        print("  Mode: Distributed threshold (interactive decrypt via DistributedPrivateKey)")
    else:
        print("  Mode: Non-distributed / fallback")

    print("\n[Setup] Creating issuer (RSA blind signature key)...")
    issuer = Issuer(rsa_bits=2048)
    issuer_pub = issuer.public_key()
    print(f"  Issuer RSA n bits: {issuer_pub[0].bit_length()}, e={issuer_pub[1]}")

    print(f"\n[Setup] Creating {num_servers} servers...")
    server_keypairs = {}
    server_public_keys = {}
    for i in range(num_servers):
        kp = generate_keypair()
        server_keypairs[i] = kp
        server_public_keys[i] = kp.public_key_bytes()
        print(f"  Server {i}: {kp.public_key_bytes().hex()[:16]}...")

    servers = []
    for i in range(num_servers):
        server = AggregatorServer(
            server_id=i,
            keypair=server_keypairs[i],
            issuer_rsa_public_key=issuer_pub,
            paillier_pk=paillier_pk,
            all_server_public_keys=server_public_keys,
            threshold_setup=threshold_setup,
            threshold_decrypt=threshold,
            threshold_finality=threshold
        )
        servers.append(server)

    # -------------------------------------------------------------------------
    # Peer auditing: auditors are the servers themselves (but they must NOT audit themselves)
    # We reuse server keypairs as auditor signing keys.
    # -------------------------------------------------------------------------
    print(f"\n[Setup] Creating peer auditors (each server audits others)...")
    auditors = []
    auditor_public_keys = {}

    for s in servers:
        auditor_public_keys[s.server_id] = server_keypairs[s.server_id].public_key_bytes()
        auditors.append(
            Auditor(
                auditor_id=s.server_id,
                keypair=server_keypairs[s.server_id],
                issuer_rsa_public_key=issuer_pub,
                all_server_public_keys=server_public_keys,
                sample_count=sample_count
            )
        )

    print("\n[Setup] Creating coordinator...")
    coordinator = Coordinator(
        paillier_pk=paillier_pk,
        all_server_public_keys=server_public_keys,
        auditor_public_keys=auditor_public_keys,
        threshold_setup=threshold_setup,
        threshold_audit=threshold,
        threshold_finality=threshold,
        threshold_decrypt=threshold
    )

    return {
        "paillier_pk": paillier_pk,
        "paillier_sk": paillier_sk,
        "threshold_setup": threshold_setup,
        "issuer": issuer,
        "issuer_pub": issuer_pub,
        "servers": servers,
        "auditors": auditors,
        "coordinator": coordinator,
        "server_public_keys": server_public_keys,
        "auditor_public_keys": auditor_public_keys,
        "threshold": threshold,
        "sample_count": sample_count,
    }


# =============================================================================
# Submissions (User side): LDP -> encode -> encrypt -> blind-token -> submit
# =============================================================================

def _issue_blind_token_local(
    issuer: Issuer,
    issuer_pub: tuple[int, int],
    rid: bytes,
    server_id: int,
    ciphertext_bytes: bytes
) -> Token:
    """
    User-side issuance:
      m <- {0,1}^256
      h = H("AuraLDP-bind" || rid || c)
      token_msg = H("AuraLDP-token" || rid || server_id || m || h)
      (B,r) = Blind(token_msg)
      σ_B = issuer.blind_sign(B)
      σ = Unblind(σ_B, r)
    """
    n, e = issuer_pub
    m = generate_random_bytes(32)
    h = H(rid, ciphertext_bytes, domain="AuraLDP-bind")

    token_msg = H(
        rid,
        canonical_int(server_id),
        m,
        h,
        domain="AuraLDP-token"
    )

    blinded_int, r_int = rsa_blind(token_msg, n, e)
    blinded_bytes = int_to_fixed_len_bytes(blinded_int, issuer.modulus_bytes_len())

    blind_sig_bytes = issuer.blind_sign(blinded_bytes)
    blind_sig_int = fixed_len_bytes_to_int(blind_sig_bytes)

    sig_int = rsa_unblind(blind_sig_int, r_int, n)
    sig_bytes = int_to_fixed_len_bytes(sig_int, issuer.modulus_bytes_len())

    return Token(m=m, h=h, sig=sig_bytes)


def simulate_user_submissions(
    setup: Dict,
    rid: bytes,
    submissions_per_server: int,
    value_range: tuple,
    epsilon: float,
    scale: int,
) -> int:
    issuer = setup["issuer"]
    issuer_pub = setup["issuer_pub"]
    servers = setup["servers"]
    paillier_pk = setup["paillier_pk"]

    min_val = float(value_range[0])
    max_val = float(value_range[1])

    print(f"\n[Submissions] Simulating {submissions_per_server} submissions per server...")
    print(f"  LDP config: epsilon={epsilon}, scale={scale}, clip=[{min_val},{max_val}]")

    total_submitted = 0
    total_value = 0

    for server in servers:
        server_id = server.server_id
        submitted = 0
        duplicates = 0

        for _ in range(submissions_per_server):
            value = random.randint(value_range[0], value_range[1])
            total_value += value

            # Laplace LDP on client
            x = np.array([float(value)], dtype=float)
            x_noisy = laplace(x, min_val=min_val, max_val=max_val, epsilon=epsilon)
            noisy_float = float(np.asarray(x_noisy).reshape(-1)[0])

            noisy_float = min(max(noisy_float, min_val), max_val)
            noisy_int = int(round(noisy_float * scale))

            # encrypt noisy value
            c = paillier_pk.encrypt(noisy_int)
            c_bytes = paillier_pk.serialize_ciphertext(c)

            # ---- Blind token issuance (paper-aligned) ----
            tok = _issue_blind_token_local(
                issuer=issuer,
                issuer_pub=issuer_pub,
                rid=rid,
                server_id=server_id,
                ciphertext_bytes=c_bytes
            )

            record = Record(
                rid=rid,
                server_id=server_id,
                req_id=generate_req_id(),
                c=c_bytes,
                tok=tok
            )

            result = server.submit(record)
            if result.error == SubmitError.OK:
                submitted += 1
            else:
                duplicates += 1

        total_submitted += submitted
        print(f"  Server {server_id}: {submitted} accepted, {duplicates} rejected")

    print(f"\n  Total: {total_submitted} submissions, raw sum (no LDP) = {total_value}")
    return total_value


# =============================================================================
# Small tests
# =============================================================================

def check_duplicate_rejection(setup: Dict, rid: bytes):
    issuer = setup["issuer"]
    issuer_pub = setup["issuer_pub"]
    server = setup["servers"][0]
    paillier_pk = setup["paillier_pk"]

    print("\n[Test] Testing duplicate rejection...")

    value = 42
    c = paillier_pk.encrypt(value)
    c_bytes = paillier_pk.serialize_ciphertext(c)

    tok = _issue_blind_token_local(issuer, issuer_pub, rid, server.server_id, c_bytes)
    req_id = generate_req_id()

    record = Record(rid=rid, server_id=server.server_id, req_id=req_id, c=c_bytes, tok=tok)
    result1 = server.submit(record)
    assert result1.error == SubmitError.OK, f"First submission should succeed, got {result1.error}"

    result2 = server.submit(record)
    assert result2.error == SubmitError.DUPLICATE_REQ_ID, "Duplicate req_id should be rejected"

    record3 = Record(rid=rid, server_id=server.server_id, req_id=generate_req_id(), c=c_bytes, tok=tok)
    result3 = server.submit(record3)
    assert result3.error == SubmitError.DUPLICATE_TAG, "Duplicate tag should be rejected"

    print("  All duplicate rejection tests passed!")


def check_wrong_server_rejection(setup: Dict, rid: bytes):
    issuer = setup["issuer"]
    issuer_pub = setup["issuer_pub"]
    server0 = setup["servers"][0]
    server1 = setup["servers"][1]
    paillier_pk = setup["paillier_pk"]

    print("\n[Test] Testing wrong server rejection...")

    value = 42
    c = paillier_pk.encrypt(value)
    c_bytes = paillier_pk.serialize_ciphertext(c)

    tok = _issue_blind_token_local(issuer, issuer_pub, rid, server0.server_id, c_bytes)

    record = Record(rid=rid, server_id=server1.server_id, req_id=generate_req_id(), c=c_bytes, tok=tok)
    result = server1.submit(record)
    assert result.error in [SubmitError.BAD_TOKEN, SubmitError.WRONG_SERVER], "Wrong server should be rejected"

    print("  Wrong server rejection test passed!")


# =============================================================================
# Orchestrator: peer auditing wrapper
# =============================================================================

class PeerAuditOrchestrator(ProtocolOrchestrator):
    """
    Same as ProtocolOrchestrator but enforces peer-audit rule:
    auditor_id == audited server_id => skip (no self-audit).
    """

    def run_round(self, rid: bytes):
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
        commits = {}
        reveals = {}

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

        seed_sigs = {}
        combined_seed = bytes(32)
        from models import H as _H
        for reveal in reveals.values():
            combined_seed = bytes(a ^ b for a, b in zip(combined_seed, reveal.random_value))
        h_seed = _H(rid, combined_seed, domain="AuraLDP-seed")

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

        # Phase 3: Auditing (peer-audit: skip self)
        print("\n[Phase 3] Auditing (peer-audit, no self-audit)...")
        round_state = self.coordinator._get_round(rid)

        for auditor in self.auditors:
            for server_id, signed_stmt in round_state.statements.items():
                if auditor.auditor_id == server_id:
                    continue

                server = self.servers[server_id]
                result = auditor.audit_server(server, signed_stmt, seed_cert)

                if result.success and result.pass_approval:
                    self.coordinator.receive_pass_approval(result.pass_approval)
                    print(f"  Auditor(Server) {auditor.auditor_id} -> Server {server_id}: PASS")
                else:
                    print(f"  Auditor(Server) {auditor.auditor_id} -> Server {server_id}: FAIL - {result.error_message}")

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
        Y_glob = self.coordinator.combine_decrypt_shares(rid, private_key=self.paillier_private_key)
        if Y_glob is not None:
            print(f"  Result: Y_glob = {Y_glob}")
        else:
            print("  Decryption incomplete")

        transcript = self.coordinator.generate_transcript(rid)
        print(f"\n=== Round {rid.hex()[:8]} complete ===")
        return transcript


# =============================================================================
# Run protocol + print stats
# =============================================================================

def run_full_protocol(setup: Dict, rid: bytes, raw_sum: int, scale: int):
    orchestrator = PeerAuditOrchestrator(
        servers=setup["servers"],
        auditors=setup["auditors"],
        coordinator=setup["coordinator"],
        paillier_private_key=setup["paillier_sk"]
    )

    transcript = orchestrator.run_round(rid)
    if not transcript:
        return None

    noisy_sum = transcript.Y_glob / scale
    noisy_mean = noisy_sum / transcript.n_glob if transcript.n_glob > 0 else 0.0

    raw_mean = raw_sum / transcript.n_glob if transcript.n_glob > 0 else 0.0
    mean_err = noisy_mean - raw_mean
    mean_se = mean_err * mean_err

    print("\n" + "=" * 60)
    print("TRANSCRIPT SUMMARY")
    print("=" * 60)
    print(f"Round ID: {transcript.rid.hex()}")
    print(f"Accepted servers: {transcript.I_acc}")
    print(f"Total records: {transcript.n_glob}")

    print(f"Raw sum (no LDP): {raw_sum}")
    print(f"Raw mean (no LDP): {raw_mean}")

    print(f"Decrypted noisy sum: {noisy_sum}")
    print(f"Decrypted noisy mean: {noisy_mean}")

    print(f"Mean error: {mean_err}")
    print(f"Mean squared error (single round): {mean_se}")

    if transcript.equivocations:
        print(f"\nWARNING: {len(transcript.equivocations)} equivocations detected!")

    return {
        "transcript": transcript,
        "raw_sum": raw_sum,
        "raw_mean": raw_mean,
        "noisy_sum": noisy_sum,
        "noisy_mean": noisy_mean,
        "mean_err": mean_err,
        "mean_se": mean_se,
    }


# =============================================================================
# CLI
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--distributed", "-d", action="store_true", help="Use TNO distributed DKG/decrypt")
    p.add_argument("--epsilon", type=float, default=1.0)
    p.add_argument("--scale", type=int, default=10_000)
    p.add_argument("--rounds", type=int, default=30, help="Number of rounds to run for MSE estimation")
    p.add_argument("--num-servers", type=int, default=3)
    p.add_argument("--threshold", type=int, default=2, help="Unified threshold t (Paillier-t / audit / finality / decrypt)")
    p.add_argument("--sample-count", type=int, default=5, help="Audit sample count per auditor per server")

    p.add_argument("--submissions-per-server", type=int, default=20)
    p.add_argument("--paillier-bits", type=int, default=512)

    p.add_argument("--min-val", type=int, default=1)
    p.add_argument("--max-val", type=int, default=100)
    return p.parse_args()


def main():
    args = parse_args()

    if args.num_servers < 2:
        raise ValueError("--num-servers must be >= 2 for peer auditing (needs 'other servers')")
    if not (1 <= args.threshold <= args.num_servers):
        raise ValueError("Invalid --threshold: must satisfy 1 <= threshold <= num_servers")

    if args.threshold > (args.num_servers - 1):
        raise ValueError(
            "Peer auditing requires --threshold <= num_servers - 1 "
            "(because a server cannot audit itself)."
        )

    if args.rounds <= 0:
        raise ValueError("--rounds must be > 0")
    if args.min_val >= args.max_val:
        raise ValueError("--min-val must be < --max-val")
    if args.epsilon <= 0:
        raise ValueError("--epsilon must be > 0")
    if args.scale <= 0:
        raise ValueError("--scale must be > 0")

    setup = create_test_setup(
        num_servers=args.num_servers,
        paillier_bits=args.paillier_bits,
        use_distributed=args.distributed,
        threshold=args.threshold,
        sample_count=args.sample_count,
    )

    try:
        test_rid = struct.pack(">Q", 0)
        check_duplicate_rejection(setup, test_rid)

        test_rid2 = struct.pack(">Q", 999)
        check_wrong_server_rejection(setup, test_rid2)

        mean_ses = []
        mean_errs = []
        raw_means = []
        noisy_means = []

        for r in range(1, args.rounds + 1):
            rid = struct.pack(">Q", r)

            print("\n" + "=" * 60)
            print(f"ROUND {r}")
            print("=" * 60)
            print(f"Config: num_servers={args.num_servers}, t={args.threshold}, sample_count={args.sample_count}")

            raw_sum = simulate_user_submissions(
                setup=setup,
                rid=rid,
                submissions_per_server=args.submissions_per_server,
                value_range=(args.min_val, args.max_val),
                epsilon=args.epsilon,
                scale=args.scale,
            )

            stats = run_full_protocol(setup, rid, raw_sum, scale=args.scale)
            if stats is None:
                raise RuntimeError(f"Round {r} failed")

            mean_ses.append(stats["mean_se"])
            mean_errs.append(stats["mean_err"])
            raw_means.append(stats["raw_mean"])
            noisy_means.append(stats["noisy_mean"])

        mse = float(np.mean(mean_ses))
        rmse = float(np.sqrt(mse))
        bias = float(np.mean(mean_errs))
        var_err = float(np.var(mean_errs, ddof=1)) if len(mean_errs) > 1 else 0.0

        print("\n" + "=" * 60)
        print("MULTI-ROUND SUMMARY (Mean)")
        print("=" * 60)
        print(f"Rounds: {args.rounds}")
        print(f"Avg raw mean: {float(np.mean(raw_means))}")
        print(f"Avg noisy mean: {float(np.mean(noisy_means))}")
        print(f"MSE(mean): {mse}")
        print(f"RMSE(mean): {rmse}")
        print(f"Bias(mean error): {bias}")
        print(f"Var(mean error): {var_err}")

        print("\n" + "=" * 60)
        print("DEMO COMPLETE")
        print("=" * 60)

    finally:
        ts = setup.get("threshold_setup")
        if ts is not None and getattr(ts, "distributed_wrapper", None) is not None:
            wrapper = ts.distributed_wrapper
            if hasattr(wrapper, "shutdown_sync"):
                wrapper.shutdown_sync()


if __name__ == "__main__":
    main()