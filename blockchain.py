import hashlib
import json
import time
import base64
from flask import Flask, jsonify, request
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

class SolidusXBlockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()
        # Solidus-X Genesis Block Initialization with Secure Previous Hash
        self.new_block(previous_hash='0000000000000000000000000000000000000000000000000000000000000000', proof=100)

    def register_node(self, address):
        """P2P Logic to add new validation nodes to the Solidus-X network architecture"""
        self.nodes.add(address)

    def new_block(self, proof, previous_hash=None):
        """Creates a new Data Block in the immutable Solidus-X ledger"""
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def add_transaction(self, sender, recipient, amount, signature):
        """Validates asymmetric digital signatures before appending transaction to pool"""
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount
        }
        
        # '0' represents system-generated Solidus-X mining coinbase reward (does not require key signature)
        if sender == "0":
            self.current_transactions.append(transaction)
            return self.last_block['index'] + 1
            
        # Cryptographic security check to verify sender identity
        is_valid = self.verify_signature(sender, signature, transaction)
        if is_valid:
            self.current_transactions.append(transaction)
            return self.last_block['index'] + 1
        else:
            raise ValueError("SOLIDUS-X SECURITY ALERT: Invalid Signature Detected! Cryptographic Verification Failed.")

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """SHA-256 Hashing for standard Solidus-X block validation integrity"""
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof):
        """Consensus mechanism to prevent malicious network sybil attacks on Solidus-X"""
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000" # Target difficulty configuration for Solidus-X

    @staticmethod
    def verify_signature(public_key_pem, signature_b64, transaction_data):
        """Core security module validating Solidus-X ECDSA public key authenticity"""
        try:
            public_key = serialization.load_pem_public_key(
                base64.b64decode(public_key_pem.encode())
            )
            signature = base64.b64decode(signature_b64.encode())
            tx_bytes = json.dumps(transaction_data, sort_keys=True).encode()
            
            public_key.verify(signature, tx_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, Exception):
            return False

# Decentralized Network Endpoint API Initialization for Solidus-X Node
app = Flask(__name__)
node_identifier = str(uuid4()).replace('-', '')
blockchain = SolidusXBlockchain()

@app.route('/mine', methods=['GET'])
def mine():
    """Triggers block validation protocol and issues coinbase incentive execution"""
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    # Reward configuration allocating 50 native Solidus-X tokens (SLX) to miner node identifier
    blockchain.add_transaction(sender="0", recipient=node_identifier, amount=50, signature="")

    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'status': "SUCCESS",
        'message': "Solidus-X Engine Layer: Block Minted Successfully",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    """Secure ledger interface to execute cryptographically secure network updates"""
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing parameters', 400

    try:
        index = blockchain.add_transaction(
            values['sender'], 
            values['recipient'], 
            values['amount'], 
            values['signature']
        )
        response = {'message': f'Secure Transaction will be added to Solidus-X Block {index}'}
        return jsonify(response), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/chain', methods=['GET'])
def full_chain():
    """Exposes internal database array data structure for state sync visualization"""
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
        'network_status': "SOLIDUS-X_SECURE_MAIN"
    }
    return jsonify(response), 200

if __name__ == '__main__':
    # Solidus-X Local Node Runtime Initialization
    app.run(host='0.0.0.0', port=5000)
