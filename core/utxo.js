/**
 * MPOINT CORE - UTXO Set Manager
 * ZERO external dependencies.
 * 
 * আনস্পেন্ট আউটপুট (UTXO) ট্র্যাকিং সিস্টেম। 
 * প্রোডাকশনে এটি LevelDB-তে স্টোর হবে, তবে কোর লজিকের জন্য এটি একটি In-Memory Map হিসেবে কাজ করে।
 */

class UTXOSet {
    constructor() {
        this.utxos = new Map(); // Key: 'txid:vout', Value: { value: BigInt, scriptPubKey: Uint8Array }
    }

    getKey(txid, vout) {
        return `${txid}:${vout}`;
    }

    /**
     * Get a UTXO by txid and vout
     */
    get(txid, vout) {
        return this.utxos.get(this.getKey(txid, vout));
    }

    /**
     * Add a new unspent output
     */
    add(txid, vout, txOut) {
        this.utxos.set(this.getKey(txid, vout), {
            value: txOut.value,
            scriptPubKey: txOut.scriptPubKey
        });
    }

    /**
     * Remove a UTXO (mark it as spent)
     */
    spend(txid, vout) {
        this.utxos.delete(this.getKey(txid, vout));
    }

    /**
     * Safely apply a full block's transactions to the UTXO set.
     * Returns an "undo" object so we can rollback if a Reorg happens.
     */
    applyBlock(block) {
        const undoData = []; // To reverse changes during a chain reorg

        for (const tx of block.txs) {
            const txid = tx.getId();

            // 1. Spend Inputs (Skip Coinbase input as it has no valid prev_out)
            if (!this.isCoinbase(tx)) {
                for (const input of tx.inputs) {
                    const utxo = this.get(input.prevTxid, input.prevVout);
                    if (!utxo) throw new Error(`Missing UTXO: ${input.prevTxid}:${input.prevVout}`);
                    
                    // Save for potential rollback, then spend
                    undoData.push({ action: 'restore', txid: input.prevTxid, vout: input.prevVout, utxo });
                    this.spend(input.prevTxid, input.prevVout);
                }
            }

            // 2. Add Outputs
            for (let i = 0; i < tx.outputs.length; i++) {
                // OP_RETURN outputs are unspendable, don't add them to UTXO set
                if (tx.outputs[i].scriptPubKey[0] !== 0x6a) {
                    this.add(txid, i, tx.outputs[i]);
                    undoData.push({ action: 'remove', txid, vout: i });
                }
            }
        }
        return undoData;
    }

    /**
     * Rollback a block (used during chain reorganizations)
     */
    undoBlock(undoData) {
        // Reverse array to undo in exact opposite order
        for (const op of undoData.reverse()) {
            if (op.action === 'restore') {
                this.utxos.set(this.getKey(op.txid, op.vout), op.utxo);
            } else if (op.action === 'remove') {
                this.spend(op.txid, op.vout);
            }
        }
    }

    isCoinbase(tx) {
        // Coinbase tx has exactly 1 input, with prevTxid = 32 zero bytes
        if (tx.inputs.length !== 1) return false;
        return tx.inputs[0].prevTxid === '0000000000000000000000000000000000000000000000000000000000000000';
    }
}

module.exports = { UTXOSet };
