"""
AuraLDP Cryptographic Utilities
- Ed25519 Signatures
- RSA-FDH Blind Signatures (for Issuer tokens)
- TNO Threshold Paillier Integration (Distributed Key Generation + Threshold Decryption)
- Fallback implementation when TNO not available
"""

import os
import hashlib
import hmac
import struct
import secrets
import math
import asyncio
import atexit
from abc import ABC, abstractmethod
from typing import Tuple, List, Optional, Dict, Any
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# ============================================================================
# Ed25519 Signature Utilities
# ============================================================================

@dataclass
class KeyPair:
    """Ed25519 key pair"""
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def sign(self, message: bytes) -> bytes:
        """Sign a message"""
        return self.private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature"""
        try:
            self.public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def public_key_bytes(self) -> bytes:
        """Get public key as bytes"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def private_key_bytes(self) -> bytes:
        """Get private key as bytes"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )


def generate_keypair() -> KeyPair:
    """Generate a new Ed25519 key pair"""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return KeyPair(private_key=private_key, public_key=public_key)


def load_public_key(key_bytes: bytes) -> Ed25519PublicKey:
    """Load public key from bytes"""
    return Ed25519PublicKey.from_public_bytes(key_bytes)


def verify_signature(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    """Verify signature with public key"""
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


# ============================================================================
# RSA-FDH Blind Signatures (Issuer tokens)
# ============================================================================

@dataclass
class RSABlindKeyPair:
    """RSA key pair for blind signatures"""
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey

    @property
    def n(self) -> int:
        return self.public_key.public_numbers().n

    @property
    def e(self) -> int:
        return self.public_key.public_numbers().e

    @property
    def d(self) -> int:
        return self.private_key.private_numbers().d

    @property
    def modulus_bytes_len(self) -> int:
        return (self.n.bit_length() + 7) // 8


def generate_rsa_blind_keypair(bits: int = 2048, e: int = 65537) -> RSABlindKeyPair:
    sk = rsa.generate_private_key(public_exponent=e, key_size=bits)
    return RSABlindKeyPair(private_key=sk, public_key=sk.public_key())


def _modinv(a: int, m: int) -> int:
    """
    Modular inverse a^{-1} mod m.

    Use Python's built-in pow for speed/safety when available (3.8+),
    otherwise fall back to an iterative extended Euclidean algorithm
    to avoid recursion depth issues with 2048-bit numbers.
    """
    a = a % m
    if a == 0:
        raise ValueError("No modular inverse for 0")

    # Python 3.8+ supports pow(a, -1, m)
    try:
        return pow(a, -1, m)  # type: ignore[arg-type]
    except TypeError:
        pass  # older Python

    # Iterative extended Euclid: find x s.t. a*x + m*y = gcd(a,m)
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r

    if r != 1:
        raise ValueError("No modular inverse (a and m not coprime)")

    return t % m


def _fdh_to_zn_star(msg: bytes, n: int, label: bytes = b"AuraLDP-RSA-FDH") -> int:
    """
    Full-domain-hash-like map into Z*_n, using SHA-256 + counter retry.
    (Good enough for a demo; if you want a tighter FDH, expand with XOF.)
    """
    counter = 0
    while True:
        digest = hashlib.sha256(label + counter.to_bytes(4, "big") + msg).digest()
        x = int.from_bytes(digest, "big") % n
        if x != 0 and math.gcd(x, n) == 1:
            return x
        counter += 1


def rsa_blind(msg: bytes, n: int, e: int) -> Tuple[int, int]:
    """
    User-side blind:
      x = FDH(msg) in Z*_n
      choose r in Z*_n
      blinded = x * r^e mod n
    Returns (blinded_int, r_int)
    """
    x = _fdh_to_zn_star(msg, n)
    while True:
        r = secrets.randbelow(n - 2) + 2
        if math.gcd(r, n) == 1:
            break
    blinded = (x * pow(r, e, n)) % n
    return blinded, r


def rsa_blind_sign(blinded: int, d: int, n: int) -> int:
    """Issuer-side blind-sign: s' = blinded^d mod n"""
    if blinded <= 0 or blinded >= n:
        # still signable mod n, but keep inputs sane
        blinded = blinded % n
    return pow(blinded, d, n)


def rsa_unblind(blind_sig: int, r: int, n: int) -> int:
    """User-side unblind: s = s' * r^{-1} mod n"""
    r_inv = _modinv(r, n)
    return (blind_sig * r_inv) % n


def rsa_verify(msg: bytes, sig: int, n: int, e: int) -> bool:
    """Verify: sig^e mod n == FDH(msg)"""
    x = _fdh_to_zn_star(msg, n)
    return pow(sig, e, n) == x


def int_to_fixed_len_bytes(x: int, length: int) -> bytes:
    """Encode int to fixed-length big-endian bytes."""
    if x < 0:
        raise ValueError("negative int")
    return x.to_bytes(length, "big")


def fixed_len_bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


# ============================================================================
# Paillier Interface (Abstract Base)
# ============================================================================

class PaillierPublicKeyBase(ABC):
    """Abstract base for Paillier public key"""

    @abstractmethod
    def encrypt(self, plaintext: int) -> Any:
        """Encrypt a plaintext value"""
        pass

    @abstractmethod
    def get_n(self) -> int:
        """Get modulus N"""
        pass

    @abstractmethod
    def get_n_squared(self) -> int:
        """Get N^2"""
        pass

    @abstractmethod
    def serialize_ciphertext(self, ciphertext: Any) -> bytes:
        """Serialize ciphertext to bytes"""
        pass

    @abstractmethod
    def deserialize_ciphertext(self, data: bytes) -> Any:
        """Deserialize ciphertext from bytes"""
        pass

    @abstractmethod
    def add_ciphertexts(self, c1: Any, c2: Any) -> Any:
        """Homomorphic addition"""
        pass

    @abstractmethod
    def validate_ciphertext(self, ciphertext: Any) -> bool:
        """Validate ciphertext"""
        pass


class PaillierPrivateKeyBase(ABC):
    """Abstract base for Paillier private key"""

    @abstractmethod
    def decrypt(self, ciphertext: Any) -> int:
        """Decrypt a ciphertext"""
        pass


# ============================================================================
# Try to import TNO Paillier
# ============================================================================

TNO_AVAILABLE = False
TNO_DISTRIBUTED_AVAILABLE = False

try:
    from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext
    from tno.mpc.encryption_schemes.paillier import PaillierPublicKey as TNOPaillierPK
    from tno.mpc.encryption_schemes.paillier import PaillierSecretKey as TNOPaillierSK
    TNO_AVAILABLE = True
    print("[crypto] TNO Paillier library loaded successfully")
except ImportError:
    print("[crypto] TNO Paillier not available")

try:
    from tno.mpc.protocols.distributed_keygen import DistributedPaillier
    from tno.mpc.communication import Pool
    TNO_DISTRIBUTED_AVAILABLE = True
    print("[crypto] TNO Distributed Paillier library loaded successfully")
except ImportError:
    print("[crypto] TNO Distributed Paillier not available")

if not TNO_AVAILABLE:
    print("[crypto] Using fallback Paillier implementation")


# ============================================================================
# TNO Paillier Wrapper (when available)
# ============================================================================

if TNO_AVAILABLE:
    class TNOPaillierPublicKey(PaillierPublicKeyBase):
        """TNO Paillier public key wrapper"""

        def __init__(self, tno_scheme: Paillier):
            self._scheme = tno_scheme
            self._pk = tno_scheme.public_key

        def encrypt(self, plaintext: int) -> PaillierCiphertext:
            return self._scheme.encrypt(plaintext)

        def get_n(self) -> int:
            return self._pk.n

        def get_n_squared(self) -> int:
            return self._pk.n ** 2

        def serialize_ciphertext(self, ciphertext: PaillierCiphertext) -> bytes:
            val = int(ciphertext.peek_value())
            byte_len = (val.bit_length() + 7) // 8 if val > 0 else 1
            return val.to_bytes(byte_len, "big")

        def deserialize_ciphertext(self, data: bytes) -> PaillierCiphertext:
            val = int.from_bytes(data, "big")
            return PaillierCiphertext(val, self._scheme)

        def add_ciphertexts(self, c1: PaillierCiphertext, c2: PaillierCiphertext) -> PaillierCiphertext:
            return c1 + c2

        def validate_ciphertext(self, ciphertext: PaillierCiphertext) -> bool:
            return math.gcd(int(ciphertext.peek_value()), self.get_n()) == 1

        @property
        def tno_key(self) -> TNOPaillierPK:
            return self._pk

        @property
        def tno_scheme(self) -> Paillier:
            return self._scheme


    class TNOPaillierPrivateKey(PaillierPrivateKeyBase):
        """TNO Paillier private key wrapper"""

        def __init__(self, tno_scheme: Paillier):
            self._scheme = tno_scheme
            self._sk = tno_scheme.secret_key
            self._pk = tno_scheme.public_key

        def decrypt(self, ciphertext: PaillierCiphertext) -> int:
            result = self._scheme.decrypt(ciphertext)
            return int(result)

        @property
        def tno_key(self) -> TNOPaillierSK:
            return self._sk


    def generate_tno_paillier_keypair(key_length: int = 2048):
        paillier_scheme = Paillier.from_security_parameter(key_length=key_length)
        return TNOPaillierPublicKey(paillier_scheme), TNOPaillierPrivateKey(paillier_scheme)


# ============================================================================
# TNO Distributed Paillier (Threshold) - when available
# ============================================================================

if TNO_DISTRIBUTED_AVAILABLE:

    class TNODistributedPaillierWrapper:
        """
        Wrapper for TNO's DistributedPaillier for threshold operations.

        IMPORTANT (Windows/aiohttp):
        - DKG and interactive decrypt must run on the SAME asyncio event loop.
          Creating a new event loop in decrypt() can deadlock/hang.
        - We keep pools alive until caller shuts them down.
        """

        def __init__(
            self,
            distributed_paillier_instances: List[DistributedPaillier],
            corruption_threshold: int,
            pools: Optional[List[Pool]] = None,
            loop: Optional[asyncio.AbstractEventLoop] = None,
            base_port: Optional[int] = None,
        ):
            self.instances = distributed_paillier_instances
            self.corruption_threshold = corruption_threshold
            self.n_parties = len(distributed_paillier_instances)
            self.pools = pools or []
            self._loop = loop
            self.base_port = base_port

            if self.instances:
                self.public_key = self.instances[0].public_key

        def encrypt(self, plaintext: int) -> PaillierCiphertext:
            return self.instances[0].encrypt(plaintext)

        async def _decrypt_async(self, ciphertext: PaillierCiphertext) -> int:
            decrypt_tasks = [inst.decrypt(ciphertext) for inst in self.instances]
            results = await asyncio.gather(*decrypt_tasks)
            return int(results[0])

        def decrypt_sync(self, ciphertext: PaillierCiphertext) -> int:
            """
            Synchronous threshold decryption (for local demo).
            Must reuse the loop that created the DistributedPaillier instances.
            """
            if self._loop is None:
                raise RuntimeError(
                    "TNODistributedPaillierWrapper has no event loop. "
                    "DKG and decrypt must share the same loop (especially on Windows)."
                )

            if self._loop.is_closed():
                raise RuntimeError("TNODistributedPaillierWrapper event loop is closed.")

            return int(self._loop.run_until_complete(self._decrypt_async(ciphertext)))

        async def shutdown(self) -> None:
            """Shutdown all associated communication pools."""
            for pool in self.pools:
                try:
                    await pool.shutdown()
                except Exception:
                    pass

        def shutdown_sync(self) -> None:
            """
            Sync shutdown helper.
            Use the same loop if available, then close it.
            """
            if not self.pools and self._loop is None:
                return

            if self._loop is not None and (not self._loop.is_closed()):
                try:
                    self._loop.run_until_complete(self.shutdown())
                finally:
                    try:
                        self._loop.close()
                    except Exception:
                        pass
                return

            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(self.shutdown())
            finally:
                loop.close()

    def setup_local_pool(server_port: int, ports: List[int]) -> Pool:
        """Create a pool for local testing"""
        pool = Pool()
        pool.add_http_server(server_port)
        for client_port in ports:
            if client_port != server_port:
                pool.add_http_client(f"client{client_port}", "127.0.0.1", client_port)
        return pool

    def generate_distributed_paillier_local_sync(
        n_parties: int = 3,
        corruption_threshold: int = 1,
        key_length: int = 128,
        prime_threshold: int = 2000,
        correct_param_biprime: int = 40,
        stat_sec_shamir: int = 40
    ) -> TNODistributedPaillierWrapper:
        base_port = 20000 + secrets.randbelow(30000)  # 20000..49999
        local_ports = [base_port + i for i in range(n_parties)]
        print(f"  [crypto] DistributedPaillier local ports: {local_ports}")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def async_setup_and_dkg():
            local_pools = [setup_local_pool(port, local_ports) for port in local_ports]
            await asyncio.sleep(0)
            async_coroutines = [
                DistributedPaillier.from_security_parameter(
                    pool,
                    corruption_threshold,
                    key_length,
                    prime_threshold,
                    correct_param_biprime,
                    stat_sec_shamir,
                    distributed=False,
                )
                for pool in local_pools
            ]
            distributed_instances = await asyncio.gather(*async_coroutines)
            return local_pools, distributed_instances

        print("  Starting TNO distributed key generation protocol...")
        local_pools, distributed_instances = loop.run_until_complete(async_setup_and_dkg())
        print("  TNO DKG protocol completed.")

        wrapper = TNODistributedPaillierWrapper(
            distributed_paillier_instances=list(distributed_instances),
            corruption_threshold=corruption_threshold,
            pools=local_pools,
            loop=loop,
            base_port=base_port,
        )

        def _cleanup():
            try:
                wrapper.shutdown_sync()
            except Exception:
                pass

        atexit.register(_cleanup)
        return wrapper


# ============================================================================
# Fallback Paillier Implementation (when TNO not available)
# ============================================================================

def _is_prime(n: int, k: int = 10) -> bool:
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """Generate a random prime"""
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(candidate):
            return candidate


def _lcm(a: int, b: int) -> int:
    """Least common multiple"""
    return abs(a * b) // math.gcd(a, b)


def _L(x: int, n: int) -> int:
    """L function: L(x) = (x - 1) / n"""
    return (x - 1) // n


class FallbackPaillierPublicKey(PaillierPublicKeyBase):
    """Fallback Paillier public key"""

    def __init__(self, n: int):
        self._n = n
        self._n_squared = n * n
        self._g = n + 1

    def encrypt(self, plaintext: int) -> int:
        while True:
            r = secrets.randbelow(self._n - 1) + 1
            if math.gcd(r, self._n) == 1:
                break
        g_m = pow(self._g, plaintext, self._n_squared)
        r_n = pow(r, self._n, self._n_squared)
        return (g_m * r_n) % self._n_squared

    def get_n(self) -> int:
        return self._n

    def get_n_squared(self) -> int:
        return self._n_squared

    def serialize_ciphertext(self, ciphertext: int) -> bytes:
        byte_len = (ciphertext.bit_length() + 7) // 8
        return ciphertext.to_bytes(byte_len or 1, "big")

    def deserialize_ciphertext(self, data: bytes) -> int:
        return int.from_bytes(data, "big")

    def add_ciphertexts(self, c1: int, c2: int) -> int:
        return (c1 * c2) % self._n_squared

    def validate_ciphertext(self, ciphertext: int) -> bool:
        return math.gcd(ciphertext, self._n) == 1


class FallbackPaillierPrivateKey(PaillierPrivateKeyBase):
    """Fallback Paillier private key"""

    def __init__(self, public_key: FallbackPaillierPublicKey, lambda_n: int, mu: int):
        self._pk = public_key
        self._lambda_n = lambda_n
        self._mu = mu

    def decrypt(self, ciphertext: int) -> int:
        n = self._pk.get_n()
        n_squared = self._pk.get_n_squared()
        c_lambda = pow(ciphertext, self._lambda_n, n_squared)
        l_val = _L(c_lambda, n)
        return (l_val * self._mu) % n


def generate_fallback_paillier_keypair(bits: int = 1024):
    """Generate fallback Paillier keypair"""
    p = _generate_prime(bits // 2)
    q = _generate_prime(bits // 2)

    n = p * q
    n_squared = n * n
    g = n + 1
    lambda_n = _lcm(p - 1, q - 1)

    g_lambda = pow(g, lambda_n, n_squared)
    l_val = _L(g_lambda, n)
    mu = _modinv(l_val, n)

    pk = FallbackPaillierPublicKey(n)
    sk = FallbackPaillierPrivateKey(pk, lambda_n, mu)

    return pk, sk


# ============================================================================
# Threshold Paillier Setup (Unified Interface)
# ============================================================================

@dataclass
class ThresholdPaillierSetup:
    """
    Threshold Paillier setup.
    Supports both TNO distributed Paillier and fallback single-party mode.
    """
    public_key: PaillierPublicKeyBase
    threshold: int
    total_servers: int
    server_shares: Dict[int, Any]
    distributed_wrapper: Any = None


@dataclass
class PartialDecryption:
    """Partial decryption from one server"""
    server_id: int
    value: Any
    proof: bytes


class ThresholdPaillierManager:
    """
    Manages threshold Paillier operations.
    Uses TNO's DistributedPaillier when available, otherwise simulates.
    """

    def __init__(self, setup: ThresholdPaillierSetup):
        self.setup = setup
        self._use_tno_distributed = (
            TNO_DISTRIBUTED_AVAILABLE and
            setup.distributed_wrapper is not None
        )

    def generate_partial_decryption(self, server_id: int, ciphertext: Any) -> PartialDecryption:
        if self._use_tno_distributed:
            wrapper = self.setup.distributed_wrapper
            partial = wrapper.partial_decrypt(server_id, ciphertext)  # type: ignore[attr-defined]
            return PartialDecryption(server_id=server_id, value=partial, proof=b"")
        return PartialDecryption(server_id=server_id, value=0, proof=b"")

    def combine_partial_decryptions(self, partials: List[PartialDecryption], ciphertext: Any) -> int:
        if len(partials) < self.setup.threshold:
            raise ValueError(f"Need {self.setup.threshold} shares, got {len(partials)}")

        if self._use_tno_distributed:
            wrapper = self.setup.distributed_wrapper
            partial_values = [p.value for p in partials]
            plaintext = wrapper.instances[partials[0].server_id].decrypt(partial_values)
            return plaintext

        return 0

    def verify_partial(self, partial: PartialDecryption, ciphertext: Any) -> bool:
        return True


def generate_threshold_setup(
    bits: int = 1024,
    threshold: int = 2,
    total_servers: int = 3,
    use_distributed: bool = False
) -> Tuple["ThresholdPaillierSetup", Optional[PaillierPrivateKeyBase]]:
    """
    Generate threshold Paillier setup.
    """
    if use_distributed and TNO_DISTRIBUTED_AVAILABLE:
        wrapper = generate_distributed_paillier_local_sync(
            n_parties=total_servers,
            corruption_threshold=threshold - 1,
            key_length=bits
        )

        class DistributedPublicKey(PaillierPublicKeyBase):
            def __init__(self, wrapper):
                self._wrapper = wrapper
                self._first_instance = wrapper.instances[0]

            def encrypt(self, plaintext: int):
                return self._wrapper.encrypt(plaintext)

            def get_n(self) -> int:
                return self._wrapper.public_key.n

            def get_n_squared(self) -> int:
                return self._wrapper.public_key.n ** 2

            def serialize_ciphertext(self, ciphertext) -> bytes:
                val = int(ciphertext.peek_value())
                byte_len = (val.bit_length() + 7) // 8 if val > 0 else 1
                return val.to_bytes(byte_len, "big")

            def deserialize_ciphertext(self, data: bytes):
                val = int.from_bytes(data, "big")
                return PaillierCiphertext(val, self._first_instance)

            def add_ciphertexts(self, c1, c2):
                return c1 + c2

            def validate_ciphertext(self, ciphertext) -> bool:
                return math.gcd(int(ciphertext.peek_value()), self.get_n()) == 1

        class DistributedPrivateKey(PaillierPrivateKeyBase):
            def __init__(self, wrapper):
                self._wrapper = wrapper

            def decrypt(self, ciphertext) -> int:
                return self._wrapper.decrypt_sync(ciphertext)

        pk = DistributedPublicKey(wrapper)
        sk = DistributedPrivateKey(wrapper)

        setup = ThresholdPaillierSetup(
            public_key=pk,
            threshold=threshold,
            total_servers=total_servers,
            server_shares={i: wrapper.instances[i] for i in range(total_servers)},
            distributed_wrapper=wrapper
        )
        return setup, sk

    elif TNO_AVAILABLE:
        pk, sk = generate_tno_paillier_keypair(bits)
        shares = {i: None for i in range(total_servers)}
        setup = ThresholdPaillierSetup(
            public_key=pk,
            threshold=threshold,
            total_servers=total_servers,
            server_shares=shares
        )
        return setup, sk

    else:
        pk, sk = generate_fallback_paillier_keypair(bits)
        shares = {i: None for i in range(total_servers)}
        setup = ThresholdPaillierSetup(
            public_key=pk,
            threshold=threshold,
            total_servers=total_servers,
            server_shares=shares
        )
        return setup, sk


# ============================================================================
# Unified Paillier Interface
# ============================================================================

def generate_paillier_keypair(bits: int = 1024):
    """
    Generate Paillier keypair using best available implementation.
    Returns (public_key, private_key) implementing the base interfaces.
    """
    if TNO_AVAILABLE:
        return generate_tno_paillier_keypair(bits)
    else:
        return generate_fallback_paillier_keypair(bits)


# ============================================================================
# Deterministic Sampling
# ============================================================================

def deterministic_sample(
    seed: bytes,
    rid: bytes,
    server_id: int,
    n_records: int,
    sample_count: int
) -> List[int]:
    """
    Deterministic sampling using HKDF-based approach.
    Returns unique indices in [0, n_records).
    """
    if sample_count >= n_records:
        return list(range(n_records))

    info = rid + struct.pack(">I", server_id)
    key = hmac.new(seed, info, hashlib.sha256).digest()

    selected = set()
    counter = 0

    while len(selected) < sample_count:
        counter_bytes = struct.pack(">Q", counter)
        h = hmac.new(key, counter_bytes, hashlib.sha256).digest()
        rand_val = int.from_bytes(h[:8], "big")

        max_valid = (2**64 // n_records) * n_records
        if rand_val < max_valid:
            index = rand_val % n_records
            selected.add(index)

        counter += 1
        if counter > sample_count * 100:
            raise RuntimeError("Sampling failed")

    return sorted(selected)


# ============================================================================
# Utility Functions
# ============================================================================

def generate_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes"""
    return os.urandom(length)


def generate_req_id() -> bytes:
    """Generate 128-bit request ID"""
    return generate_random_bytes(16)


def generate_rid(round_number: int) -> bytes:
    """Generate round ID from round number"""
    return struct.pack(">Q", round_number)