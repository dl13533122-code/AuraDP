"""
AuraLDP FastAPI HTTP Server
Provides REST API for the aggregator server
Supports TNO Paillier integration
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
import base64
import uvicorn

from models import Record, Token, MerkleDirection
from server import AggregatorServer, Issuer, SubmitError
from crypto import (
    generate_keypair, generate_paillier_keypair,
    generate_threshold_setup, PaillierPublicKeyBase
)


# ============================================================================
# Pydantic Models for API
# ============================================================================

class TokenRequest(BaseModel):
    """Request to issue a token"""
    rid: str = Field(..., description="Round ID (hex)")
    server_id: int = Field(..., description="Target server ID")
    ciphertext: str = Field(..., description="Paillier ciphertext (base64)")


class TokenResponse(BaseModel):
    """Token response"""
    m: str = Field(..., description="Random nonce (base64)")
    h: str = Field(..., description="Binding hash (base64)")
    sig: str = Field(..., description="Signature (base64)")


class SubmitRequest(BaseModel):
    """User submission request"""
    rid: str = Field(..., description="Round ID (hex)")
    server_id: int = Field(..., description="Server ID")
    req_id: str = Field(..., description="Request ID (base64)")
    ciphertext: str = Field(..., description="Paillier ciphertext (base64)")
    token: TokenResponse


class SubmitResponse(BaseModel):
    """Submit response"""
    success: bool
    index: Optional[int] = None
    error: Optional[str] = None


class BatchStatementResponse(BaseModel):
    """Batch statement response"""
    rid: str
    server_id: int
    n_i: int
    root_i: str
    C_i: str
    signature: str


class MerklePathItem(BaseModel):
    """Single step in Merkle path"""
    direction: str
    sibling_hash: str


class AuditOpenItemResponse(BaseModel):
    """Opened record for audit"""
    index: int
    ciphertext: str
    token: TokenResponse
    leaf_hash: str
    merkle_path: List[MerklePathItem]


class AuditOpenRequest(BaseModel):
    """Request to open records for audit"""
    rid: str
    indices: List[int]


class SeedCommitRequest(BaseModel):
    """Seed commit request"""
    rid: str


class SeedCommitResponse(BaseModel):
    """Seed commit response"""
    rid: str
    server_id: int
    commit: str


class SeedRevealResponse(BaseModel):
    """Seed reveal response"""
    rid: str
    server_id: int
    random_value: str
    nonce: str


class FinalitySignRequest(BaseModel):
    """Request for finality signature"""
    rid: str
    h_glob: str


class FinalitySignResponse(BaseModel):
    """Finality signature response"""
    rid: str
    server_id: int
    signature: str


class PublicKeyInfo(BaseModel):
    """Public key information"""
    n: str
    server_public_key: str
    issuer_public_key: str


# ============================================================================
# Server Instance
# ============================================================================

_server: Optional[AggregatorServer] = None
_issuer: Optional[Issuer] = None
_paillier_pk: Optional[PaillierPublicKeyBase] = None


def get_server() -> AggregatorServer:
    global _server
    if _server is None:
        raise HTTPException(status_code=500, detail="Server not initialized")
    return _server


def get_issuer() -> Issuer:
    global _issuer
    if _issuer is None:
        raise HTTPException(status_code=500, detail="Issuer not initialized")
    return _issuer


# ============================================================================
# FastAPI App
# ============================================================================

app = FastAPI(
    title="AuraLDP Aggregator Server",
    description="Privacy-preserving data collection with verifiable aggregation",
    version="1.0.0"
)


@app.on_event("startup")
async def startup():
    """Initialize server on startup"""
    global _server, _issuer, _paillier_pk

    print("Initializing AuraLDP server...")

    server_keypair = generate_keypair()
    issuer_keypair = generate_keypair()

    # Use threshold setup
    threshold_setup, paillier_sk = generate_threshold_setup(
        bits=512,
        threshold=2,
        total_servers=3
    )

    _paillier_pk = threshold_setup.public_key
    _issuer = Issuer(issuer_keypair)

    _server = AggregatorServer(
        server_id=0,
        keypair=server_keypair,
        issuer_public_key=issuer_keypair.public_key_bytes(),
        paillier_pk=_paillier_pk,
        all_server_public_keys={0: server_keypair.public_key_bytes()},
        threshold_setup=threshold_setup,
        threshold_decrypt=2,
        threshold_finality=1
    )

    print(f"Server initialized with ID: {_server.server_id}")


@app.get("/v1/info", response_model=PublicKeyInfo)
async def get_info():
    """Get server public key information"""
    server = get_server()
    issuer = get_issuer()

    return PublicKeyInfo(
        n=hex(_paillier_pk.get_n()),
        server_public_key=base64.b64encode(server.keypair.public_key_bytes()).decode(),
        issuer_public_key=base64.b64encode(issuer.public_key_bytes()).decode()
    )


@app.post("/v1/token", response_model=TokenResponse)
async def issue_token(request: TokenRequest):
    """Issue a token for a submission"""
    issuer = get_issuer()

    rid = bytes.fromhex(request.rid)
    c = base64.b64decode(request.ciphertext)

    tok = issuer.issue_token(rid, request.server_id, c)

    return TokenResponse(
        m=base64.b64encode(tok.m).decode(),
        h=base64.b64encode(tok.h).decode(),
        sig=base64.b64encode(tok.sig).decode()
    )


@app.post("/v1/submit", response_model=SubmitResponse)
async def submit(request: SubmitRequest):
    """Submit an encrypted record"""
    server = get_server()

    try:
        rid = bytes.fromhex(request.rid)
        req_id = base64.b64decode(request.req_id)
        c = base64.b64decode(request.ciphertext)

        tok = Token(
            m=base64.b64decode(request.token.m),
            h=base64.b64decode(request.token.h),
            sig=base64.b64decode(request.token.sig)
        )

        record = Record(
            rid=rid,
            server_id=request.server_id,
            req_id=req_id,
            c=c,
            tok=tok
        )

        result = server.submit(record)

        if result.error == SubmitError.OK:
            return SubmitResponse(success=True, index=result.index)
        else:
            return SubmitResponse(success=False, error=result.error.value)

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/round/{rid}/finalize-batch", response_model=Optional[BatchStatementResponse])
async def finalize_batch(rid: str):
    """Finalize batch for a round"""
    server = get_server()

    rid_bytes = bytes.fromhex(rid)
    signed_stmt = server.finalize_batch(rid_bytes)

    if signed_stmt is None:
        return None

    stmt = signed_stmt.stmt
    return BatchStatementResponse(
        rid=stmt.rid.hex(),
        server_id=stmt.server_id,
        n_i=stmt.n_i,
        root_i=base64.b64encode(stmt.root_i).decode(),
        C_i=base64.b64encode(stmt.C_i).decode(),
        signature=base64.b64encode(signed_stmt.sig_server).decode()
    )


@app.post("/v1/audit/open", response_model=List[AuditOpenItemResponse])
async def audit_open(request: AuditOpenRequest):
    """Open records for audit"""
    server = get_server()

    try:
        rid = bytes.fromhex(request.rid)
        items = server.audit_open(rid, request.indices)

        responses = []
        for item in items:
            path = []
            for direction, sibling in item.merkle_proof.path:
                path.append(MerklePathItem(
                    direction="left" if direction == MerkleDirection.LEFT else "right",
                    sibling_hash=base64.b64encode(sibling).decode()
                ))

            responses.append(AuditOpenItemResponse(
                index=item.index,
                ciphertext=base64.b64encode(item.c).decode(),
                token=TokenResponse(
                    m=base64.b64encode(item.tok.m).decode(),
                    h=base64.b64encode(item.tok.h).decode(),
                    sig=base64.b64encode(item.tok.sig).decode()
                ),
                leaf_hash=base64.b64encode(item.merkle_proof.leaf_hash).decode(),
                merkle_path=path
            ))

        return responses

    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/seed/commit", response_model=SeedCommitResponse)
async def seed_commit(request: SeedCommitRequest):
    """Generate seed commitment"""
    server = get_server()

    rid = bytes.fromhex(request.rid)
    commit = server.generate_seed_commit(rid)

    return SeedCommitResponse(
        rid=commit.rid.hex(),
        server_id=commit.server_id,
        commit=base64.b64encode(commit.commit).decode()
    )


@app.get("/v1/seed/reveal/{rid}", response_model=Optional[SeedRevealResponse])
async def seed_reveal(rid: str):
    """Get seed reveal"""
    server = get_server()

    rid_bytes = bytes.fromhex(rid)
    reveal = server.get_seed_reveal(rid_bytes)

    if reveal is None:
        return None

    return SeedRevealResponse(
        rid=reveal.rid.hex(),
        server_id=reveal.server_id,
        random_value=base64.b64encode(reveal.random_value).decode(),
        nonce=base64.b64encode(reveal.nonce).decode()
    )


@app.post("/v1/finality/sign", response_model=FinalitySignResponse)
async def finality_sign(request: FinalitySignRequest):
    """Sign finality message"""
    server = get_server()

    rid = bytes.fromhex(request.rid)
    h_glob = base64.b64decode(request.h_glob)

    sig = server.sign_finality(rid, h_glob)

    return FinalitySignResponse(
        rid=request.rid,
        server_id=server.server_id,
        signature=base64.b64encode(sig).decode()
    )


@app.get("/v1/round/{rid}/status")
async def round_status(rid: str):
    """Get round status"""
    server = get_server()

    rid_bytes = bytes.fromhex(rid)
    count = server.get_record_count(rid_bytes)
    stmt = server.get_batch_statement(rid_bytes)

    return {
        "rid": rid,
        "record_count": count,
        "is_finalized": stmt is not None
    }


# ============================================================================
# Main
# ============================================================================

def run_server(host: str = "0.0.0.0", port: int = 8000):
    """Run the server"""
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
