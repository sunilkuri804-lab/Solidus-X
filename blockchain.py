
cd ~/solidus-x

cat > requirements.txt <<'EOF'
Flask>=3.0,<4
cryptography>=43,<47
requests>=2.31,<3
pytest>=8,<9
EOF

cat > blockchain.py <<'PY'
import os
import json
import time
import hashlib
import secrets
import threading
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.exceptions import InvalidSignature


NETWORK = "SOLIDUS-X"
TICKER = "SLDX"
CONSENSUS = "PoS"

BLOCK_TIME = 3
FEE_RATE = 0.0001
P2P_PORT = 29333

DATA_DIR = "data"
CHAIN_FILE = os.path.join(DATA_DIR, "chain.json")
VALIDATORS_FILE = os.path.join(DATA_DIR, "validators.json")
PEERS_FILE = os.path.join(DATA_DIR, "peers.json")

TREASURY_ADDRESS = "SLDX_TREASURY"


def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def canonical_json(data) -> str:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    )


def atomic_write(path: str, data):
    temp = path + ".tmp"

    with open(temp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    os.replace(temp, path)


def load_json(path: str, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def public_key_to_address(public_key_hex: str) -> str:
    digest = hashlib.sha256(
        bytes.fromhex(public_key_hex)
    ).hexdigest()

    return "sld" + digest[:40]


def generate_wallet():
    private_key = ec.generate_private_key(ec.SECP256K1())

    private_bytes = private_key.private_numbers().private_value.to_bytes(
        32,
        "big"
    )

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )

    public_hex = public_key.hex()
    address = public_key_to_address(public_hex)

    return {
        "network": NETWORK,
        "ticker": TICKER,
        "address": address,
        "public_key": public_hex,
        "private_key": private_bytes.hex()
    }


def private_key_from_hex(private_hex: str):
    value = int(private_hex, 16)

    return ec.derive_private_key(
        value,
        ec.SECP256K1()
    )


def sign_transaction(transaction: dict, private_key_hex: str) -> str:
    private_key = private_key_from_hex(private_key_hex)

    payload = {
        "sender": transaction["sender"],
        "recipient": transaction["recipient"],
        "amount": transaction["amount"],
        "fee": transaction["fee"],
        "nonce": transaction["nonce"]
    }

    message = canonical_json(payload).encode()

    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    r, s = decode_dss_signature(signature)

    return f"{r:x}:{s:x}"


def verify_transaction_signature(transaction: dict) -> bool:
    try:
        public_hex = transaction["public_key"]

        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            bytes.fromhex(public_hex)
        )

        expected_address = public_key_to_address(public_hex)

        if transaction["sender"] != expected_address:
            return False

        r_hex, s_hex = transaction["signature"].split(":")
        r = int(r_hex, 16)
        s = int(s_hex, 16)

        signature = encode_dss_signature(r, s)

        payload = {
            "sender": transaction["sender"],
            "recipient": transaction["recipient"],
            "amount": transaction["amount"],
            "fee": transaction["fee"],
            "nonce": transaction["nonce"]
        }

        message = canonical_json(payload).encode()

        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )

        return True

    except (ValueError, KeyError, InvalidSignature, TypeError):
        return False


@dataclass
class Block:
    index: int
    timestamp: float
    transactions: List[dict]
    previous_hash: str
    validator: str
    reward: float
    hash: str = ""

    def calculate_hash(self):
        data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "validator": self.validator,
            "reward": self.reward
        }

        return sha256(canonical_json(data))

    def finalize(self):
        self.hash = self.calculate_hash()
        return self.hash


class SolidusBlockchain:

    def __init__(self):
        ensure_data_dir()

        self.lock = threading.RLock()

        self.chain = load_json(CHAIN_FILE, [])
        self.validators = load_json(VALIDATORS_FILE, {})
        self.peers = load_json(PEERS_FILE, [])

        self.pending_transactions = []

        if not self.chain:
            self.create_genesis()

    # -----------------------------
    # Persistence
    # -----------------------------

    def save(self):
        atomic_write(CHAIN_FILE, self.chain)
        atomic_write(VALIDATORS_FILE, self.validators)
        atomic_write(PEERS_FILE, self.peers)

    # -----------------------------
    # Genesis
    # -----------------------------

    def create_genesis(self):
        genesis = Block(
            index=0,
            timestamp=time.time(),
            transactions=[],
            previous_hash="0" * 64,
            validator="GENESIS",
            reward=0
        )

        genesis.finalize()

        self.chain = [asdict(genesis)]
        self.save()

    # -----------------------------
    # Chain
    # -----------------------------

    @property
    def height(self):
        return len(self.chain) - 1

    def latest_block(self):
        return self.chain[-1]

    def calculate_block_hash(self, block):
        data = {
            "index": block["index"],
            "timestamp": block["timestamp"],
            "transactions": block["transactions"],
            "previous_hash": block["previous_hash"],
            "validator": block["validator"],
            "reward": block["reward"]
        }

        return sha256(canonical_json(data))

    # -----------------------------
    # Validators / PoS
    # -----------------------------

    def register_validator(self, address: str, stake: float):

        if not address.startswith("sld"):
            raise ValueError("Invalid validator address")

        if stake <= 0:
            raise ValueError("Stake must be greater than zero")

        self.validators[address] = {
            "stake": float(stake),
            "registered_at": time.time()
        }

        self.save()

        return self.validators[address]

    def select_validator(self) -> Optional[str]:

        if not self.validators:
            return None

        total_stake = sum(
            item["stake"]
            for item in self.validators.values()
        )

        if total_stake <= 0:
            return None

        # Deterministic weighted selection for prototype.
        seed = int(
            sha256(
                self.latest_block()["hash"]
                .encode()
            ),
            16
        )

        target = seed % int(total_stake * 1_000_000)

        cumulative = 0

        for address, item in sorted(self.validators.items()):
            cumulative += int(item["stake"] * 1_000_000)

            if target < cumulative:
                return address

        return next(iter(self.validators))

    # -----------------------------
    # Transactions
    # -----------------------------

    def transaction_id(self, tx):
        return sha256(canonical_json(tx))

    def add_transaction(self, tx: dict):

        required = [
            "sender",
            "recipient",
            "amount",
            "fee",
            "nonce",
            "public_key",
            "signature"
        ]

        for key in required:
            if key not in tx:
                raise ValueError(f"Missing field: {key}")

        amount = float(tx["amount"])
        fee = float(tx["fee"])

        if amount <= 0:
            raise ValueError("Amount must be greater than zero")

        if fee < 0:
            raise ValueError("Invalid fee")

        if not verify_transaction_signature(tx):
            raise ValueError("Invalid transaction signature")

        tx = dict(tx)
        tx["amount"] = amount
        tx["fee"] = fee
        tx["nonce"] = int(tx["nonce"])

        self.pending_transactions.append(tx)

        return self.transaction_id(tx)

    # -----------------------------
    # PoS Block Production
    # -----------------------------

    def produce_block(self):

        with self.lock:

            validator = self.select_validator()

            if validator is None:
                raise ValueError(
                    "No validator registered. Register stake first."
                )

            transactions = list(self.pending_transactions)

            fee_total = sum(
                float(tx["fee"])
                for tx in transactions
            )

            block = Block(
                index=len(self.chain),
                timestamp=time.time(),
                transactions=transactions,
                previous_hash=self.latest_block()["hash"],
                validator=validator,
                reward=fee_total
            )

            block.finalize()

            self.chain.append(asdict(block))
            self.pending_transactions.clear()

            self.save()

            return asdict(block)

    # -----------------------------
    # Validation
    # -----------------------------

    def validate_chain(self):

        if not self.chain:
            return False

        for i, block in enumerate(self.chain):

            expected_hash = self.calculate_block_hash(block)

            if block["hash"] != expected_hash:
                return False

            if i == 0:
                if block["previous_hash"] != "0" * 64:
                    return False
                continue

            previous = self.chain[i - 1]

            if block["previous_hash"] != previous["hash"]:
                return False

            if block["index"] != i:
                return False

            for tx in block["transactions"]:

                if not verify_transaction_signature(tx):
                    return False

        return True

    # -----------------------------
    # P2P
    # -----------------------------

    def register_peer(self, peer: str):

        if peer not in self.peers:
            self.peers.append(peer)
            self.save()

        return self.peers

    # -----------------------------
    # Balance
    # -----------------------------

    def balance(self, address: str):

        balance = 0.0

        for block in self.chain:

            for tx in block["transactions"]:

                if tx["recipient"] == address:
                    balance += float(tx["amount"])

                if tx["sender"] == address:
                    balance -= float(tx["amount"])
                    balance -= float(tx["fee"])

            if block["validator"] == address:
                balance += float(block["reward"])

        return round(balance, 8)

    # -----------------------------
    # Status
    # -----------------------------

    def status(self):

        return {
            "network": NETWORK,
            "ticker": TICKER,
            "consensus": CONSENSUS,
            "height": self.height,
            "block_time": BLOCK_TIME,
            "fee_rate": FEE_RATE,
            "validators": len(self.validators),
            "peers": len(self.peers),
            "pending_transactions": len(
                self.pending_transactions
            ),
            "chain_valid": self.validate_chain()
        }


# ==========================================
# Flask API
# ==========================================

app = Flask(__name__)

blockchain = SolidusBlockchain()


@app.get("/")
def home():

    return jsonify({
        "project": NETWORK,
        "ticker": TICKER,
        "consensus": CONSENSUS,
        "status": "development",
        "message": "Solidus-X blockchain node"
    })


@app.get("/status")
def get_status():
    return jsonify(blockchain.status())


@app.get("/chain")
def get_chain():

    return jsonify({
        "length": len(blockchain.chain),
        "chain": blockchain.chain
    })


@app.get("/validate")
def validate():

    return jsonify({
        "valid": blockchain.validate_chain()
    })


@app.get("/balance/<address>")
def get_balance(address):

    return jsonify({
        "address": address,
        "balance": blockchain.balance(address)
    })


@app.post("/wallet")
def create_wallet_api():

    return jsonify(generate_wallet())


@app.post("/transactions")
def create_transaction():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "JSON body required"
        }), 400

    try:
        tx_id = blockchain.add_transaction(data)

        return jsonify({
            "success": True,
            "transaction_id": tx_id,
            "pending": len(
                blockchain.pending_transactions
            )
        }), 201

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


@app.post("/validators")
def add_validator():

    data = request.get_json(silent=True) or {}

    address = data.get("address")
    stake = data.get("stake")

    try:

        result = blockchain.register_validator(
            address,
            float(stake)
        )

        return jsonify({
            "success": True,
            "validator": result
        }), 201

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


@app.post("/produce-block")
def produce_block():

    try:

        block = blockchain.produce_block()

        return jsonify({
            "success": True,
            "block": block
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


@app.post("/peers")
def add_peer():

    data = request.get_json(silent=True) or {}

    peer = data.get("peer")

    if not peer:
        return jsonify({
            "error": "peer required"
        }), 400

    peers = blockchain.register_peer(peer)

    return jsonify({
        "success": True,
        "peers": peers
    })


if __name__ == "__main__":

    print("=" * 50)
    print("SOLIDUS-X NODE")
    print("=" * 50)
    print(f"Network:   {NETWORK}")
    print(f"Ticker:    {TICKER}")
    print(f"Consensus: {CONSENSUS}")
    print(f"Height:    {blockchain.height}")
    print(f"Peers:     {len(blockchain.peers)}")
    print(f"Validators:{len(blockchain.validators)}")
    print("=" * 50)

    app.run(
        host="0.0.0.0",
        port=P2P_PORT,
        debug=False
    )
PY

mkdir -p tests

cat > tests/test_blockchain.py <<'PY'
from blockchain import (
    SolidusBlockchain,
    generate_wallet,
    sign_transaction,
    FEE_RATE
)


def test_wallet_creation():

    wallet = generate_wallet()

    assert wallet["address"].startswith("sld")
    assert len(wallet["private_key"]) == 64
    assert len(wallet["public_key"]) > 0


def test_transaction_signature():

    chain = SolidusBlockchain()

    wallet = generate_wallet()
    receiver = generate_wallet()

    tx = {
        "sender": wallet["address"],
        "recipient": receiver["address"],
        "amount": 10,
        "fee": 10 * FEE_RATE,
        "nonce": 1,
        "public_key": wallet["public_key"]
    }

    tx["signature"] = sign_transaction(
        tx,
        wallet["private_key"]
    )

    tx_id = chain.add_transaction(tx)

    assert tx_id
    assert len(chain.pending_transactions) == 1


def test_genesis_chain():

    chain = SolidusBlockchain()

    assert len(chain.chain) >= 1
    assert chain.chain[0]["index"] == 0
    assert chain.validate_chain() is True


def test_pos_validator():

    chain = SolidusBlockchain()

    wallet = generate_wallet()

    chain.register_validator(
        wallet["address"],
        100
    )

    selected = chain.select_validator()

    assert selected == wallet["address"]


def test_block_production():

    chain = SolidusBlockchain()

    wallet = generate_wallet()

    chain.register_validator(
        wallet["address"],
        100
    )

    block = chain.produce_block()

    assert block["validator"] == wallet["address"]
    assert block["index"] >= 1
    assert chain.validate_chain() is True
PY

cat > .gitignore <<'EOF'
__pycache__/
*.pyc
.pytest_cache/
.venv/
venv/
.env
data/chain.json
data/validators.json
data/peers.json
wallet/
EOF

python -m pip install --upgrade pip
pip install -r requirements.txt

python -m pytest -q

git add blockchain.py requirements.txt tests/test_blockchain.py .gitignore
git commit -m "Implement Solidus-X PoS blockchain core"
git push origin main
