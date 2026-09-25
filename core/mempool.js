/**
 * MPOINT CORE - Mempool (Unconfirmed Transactions)
 */

class Mempool {
    constructor() {
        this.txs = new Map(); // Key: txid, Value: Transaction
        this.spentOutpoints = new Set(); // Tracks UTXOs being spent in the mempool to prevent double-spends
    }

    addTx(tx) {
        const txid = tx.getId();
        if (this.txs.has(txid)) return; // Already have it

        // Prevent double spends within the mempool itself
        for (const input of tx.inputs) {
            const outpoint = `${input.prevTxid}:${input.prevVout}`;
            if (this.spentOutpoints.has(outpoint)) {
                throw new Error("Double spend detected in mempool");
            }
        }

        // Add to mempool
        this.txs.set(txid, tx);
        for (const input of tx.inputs) {
            this.spentOutpoints.add(`${input.prevTxid}:${input.prevVout}`);
        }
    }

    /**
     * Called when a new block is mined to clear confirmed txs from the mempool
     */
    removeConfirmed(block) {
        for (const tx of block.txs) {
            const txid = tx.getId();
            if (this.txs.has(txid)) {
                const memTx = this.txs.get(txid);
                for (const input of memTx.inputs) {
                    this.spentOutpoints.delete(`${input.prevTxid}:${input.prevVout}`);
                }
                this.txs.delete(txid);
            }
        }
    }

    getTransactions() {
        return Array.from(this.txs.values());
    }
}

module.exports = { Mempool };
