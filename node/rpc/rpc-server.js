/**
 * MPOINT NODE - JSON-RPC Server
 * ZERO external dependencies. Uses Node's native 'http' module.
 * 
 * নোড লোকালহোস্টে একটি HTTP সার্ভার রান করবে। 
 * CLI টুল বা অন্যান্য অ্যাপ্লিকেশন JSON-RPC এর মাধ্যমে এই সার্ভারকে কল করে নোডের স্টেট জানতে পারবে।
 */

const http = require('node:http');

class RpcServer {
    /**
     * @param {NodeServer} node - The running Mpoint Node instance
     * @param {number} port - RPC Port (Default: 8332, same as Bitcoin)
     */
    constructor(node, port = 8332) {
        this.node = node;
        this.port = port;
        this.server = http.createServer(this._handleRequest.bind(this));
    }

    start() {
        return new Promise((resolve) => {
            this.server.listen(this.port, '127.0.0.1', () => {
                console.log(`[RPC] Server listening on 127.0.0.1:${this.port}`);
                resolve();
            });
        });
    }

    stop() {
        if (this.server) this.server.close();
    }

    _handleRequest(req, res) {
        // Only accept POST requests for JSON-RPC
        if (req.method !== 'POST') {
            res.writeHead(405, { 'Content-Type': 'text/plain' });
            res.end('Method Not Allowed. Use POST JSON-RPC.\n');
            return;
        }

        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            try {
                const requestObj = JSON.parse(body);
                this._processRpc(requestObj, res);
            } catch (e) {
                this._sendResponse(res, null, { code: -32700, message: "Parse error" }, null);
            }
        });
    }

    _processRpc(requestObj, res) {
        const { method, params = [], id = null } = requestObj;

        let result = null;
        let error = null;

        try {
            switch (method) {
                case 'getblockcount':
                    result = this.node.chain.getHeight();
                    break;
                    
                case 'getbestblockhash':
                    result = this.node.chain.getTip().header.getId();
                    break;
                    
                case 'getconnectioncount':
                    result = this.node.peerManager.getConnectedCount();
                    break;

                case 'getpeerinfo':
                    result = Array.from(this.node.peerManager.peers.values())
                        .filter(p => p.handshakeComplete)
                        .map(p => ({
                            address: p.peerAddress,
                            inbound: p.isInbound,
                            height: p.versionData ? p.versionData.best_height : 0
                        }));
                    break;
                    
                case 'stop':
                    result = "Mpoint node stopping...";
                    this._sendResponse(res, result, null, id);
                    setTimeout(() => process.exit(0), 1000); // Allow response to send before exiting
                    return;

                default:
                    error = { code: -32601, message: `Method not found: ${method}` };
            }
        } catch (err) {
            error = { code: -32603, message: err.message };
        }

        this._sendResponse(res, result, error, id);
    }

    _sendResponse(res, result, error, id) {
        const responseObj = {
            jsonrpc: "2.0",
            result: result,
            error: error,
            id: id
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(responseObj) + '\n');
    }
}

module.exports = { RpcServer };
