/**
 * MPOINT CORE - Chain State Machine
 * 
 * ব্লকচেইনের মেইন ইঞ্জিন। এটি ব্লকের ভ্যালিডেশন, PoW চেক, এবং ফর্ক রিঅর্গানাইজেশন (Reorg) নিয়ন্ত্রণ করে।
 */

const { UTXOSet } = require('./utxo.js');
const { Mempool } = require('./mempool.js');
const { calculateMerkleRoot } = require('./block.js');
const { checkProofOfWork, getBlockReward, targetToBits, bitsToTarget, MAX_TARGET } = require('./consensus.js');
const { executeScript } = require('./script.js');
const { verify, decodePublicKey } = require('./secp256k1.js');
const { decodeDER } = require('./builder.js');
const { bytesToHex } = require('./tx.js');

class Chain {
    constructor() {
        this.blocks = [];      // Array of verified Blocks (The Main Chain)
        this.utxo = new UTXOSet();
        this.mempool = new Mempool();
    }

    getTip() {
        return this.blocks.length > 0 ? this.blocks[this.blocks.length - 1] : null;
    }

    getHeight() {
        return this.blocks.length;
    }

    /**
     * Calculates Cumulative Work of a chain.
     * Work = 2^256 / (target + 1). (This is exactly how Bitcoin resolves ties!)
     */
    static getWork(bits) {
        const target = bitsToTarget(bits);
        // Using 2n ** 256n natively supported by JS BigInt
        return (2n ** 256n) / (target + 1n);
    }

    /**
     * Validate an entire block and all its transactions
     */
    validateBlock(block, isGenesis = false) {
        const header = block.header;
        const blockId = header.getId();

        // 1. Proof of Work Check
        if (!checkProofOfWork(header.getHash(), header.bits)) {
            throw new Error(`Invalid Proof of Work for block ${blockId}`);
        }

        // 2. Merkle Root Check
        const calculatedRoot = calculateMerkleRoot(block.txs.map(tx => tx.getHash()));
        if (bytesToHex(header.merkleRoot) !== bytesToHex(calculatedRoot)) {
            throw new Error(`Invalid Merkle Root in block ${blockId}`);
        }

        const tip = this.getTip();
        
        // 3. Chain Link Check (unless it's Genesis)
        if (!isGenesis && tip) {
            if (bytesToHex(header.prevBlockHash) !== tip.header.getId()) {
                throw new Error("Block does not connect to the current chain tip (Fork detected)");
            }
            
            // Timestamp must be > median of last 11 blocks
            const last11 = this.blocks.slice(-11).map(b => b.header.timestamp).sort((a, b) => a - b);
            const medianTime = last11[Math.floor(last11.length / 2)] || 0;
            if (header.timestamp <= medianTime) {
                throw new Error("Block timestamp is too old");
            }
            // Timestamp must not be more than 2 hours in the future
            if (header.timestamp > Math.floor(Date.now() / 1000) + 7200) {
                throw new Error("Block timestamp is too far in the future");
            }
        }

        // 4. Transaction Verification
        if (block.txs.length === 0) throw new Error("Block must contain at least a Coinbase transaction");
        if (!this.utxo.isCoinbase(block.txs[0])) throw new Error("First transaction must be Coinbase");

        let totalFees = 0n;

        // Start from index 1 (Skip Coinbase for input checking)
        for (let i = 1; i < block.txs.length; i++) {
            const tx = block.txs[i];
            if (this.utxo.isCoinbase(tx)) throw new Error("Only the first transaction can be Coinbase");

            let inputSum = 0n;
            let outputSum = 0n;

            // Verify Inputs
            for (let inIdx = 0; inIdx < tx.inputs.length; inIdx++) {
                const input = tx.inputs[inIdx];
                const prevUtxo = this.utxo.get(input.prevTxid, input.prevVout);
                
                if (!prevUtxo) throw new Error(`Missing or Spent UTXO: ${input.prevTxid}:${input.prevVout}`);
                inputSum += prevUtxo.value;

                // Script Verification (The Cryptographic Lock!)
                const txContext = {
                    checkSig: (sigBytes, pubKeyBytes) => {
                        const rawSig = sigBytes.slice(0, -1);
                        const sigHashType = sigBytes[sigBytes.length - 1];
                        if (sigHashType !== 0x01) return false;
                        
                        const expectedSigHash = tx.getSigHash(inIdx, prevUtxo.scriptPubKey);
                        
                        try {
                            const signature = decodeDER(rawSig);
                            return verify(expectedSigHash, pubKeyBytes, signature);
                        } catch (e) {
                            return false;
                        }
                    }
                };

                const isValid = executeScript(input.scriptSig, prevUtxo.scriptPubKey, txContext);
                if (!isValid) throw new Error(`Script verification failed for tx ${tx.getId()} input ${inIdx}`);
            }

            // Verify Outputs
            for (const output of tx.outputs) {
                if (output.value < 0n) throw new Error("Negative output value");
                outputSum += output.value;
            }

            if (inputSum < outputSum) throw new Error("Transaction outputs exceed inputs (Value created out of thin air!)");
            totalFees += (inputSum - outputSum);
        }

        // 5. Coinbase Reward Check
        const expectedReward = getBlockReward(this.getHeight()) + totalFees;
        let actualCoinbaseValue = 0n;
        for (const out of block.txs[0].outputs) actualCoinbaseValue += out.value;
        
        if (actualCoinbaseValue > expectedReward) {
            throw new Error(`Coinbase creates too much MPT. Expected max ${expectedReward}, got ${actualCoinbaseValue}`);
        }

        return true;
    }

    /**
     * Add a block to the main chain. 
     * In a full node, this handles Reorgs if it doesn't build on the tip.
     */
    addBlock(block, isGenesis = false) {
        try {
            // Validate all consensus rules
            this.validateBlock(block, isGenesis);
            
            // Commit changes to UTXO Set
            this.utxo.applyBlock(block);
            
            // Push to chain
            this.blocks.push(block);
            
            // Clean mempool
            this.mempool.removeConfirmed(block);
            
            return true;
        } catch (e) {
            // In a production node, if this is an orphan/fork block, we store it in a secondary Map
            // and calculate cumulative work to see if we should trigger a UTXO rollback/reorg.
            // For v1 core mechanics, we strictly enforce it connects to the tip.
            throw e;
        }
    }
}

module.exports = { Chain };
