#!/usr/bin/env node
/**
 * MPOINT FULL NODE - Main Startup Script
 * 
 * সার্ভার স্টার্ট করার কমান্ড। এটি P2P নেটওয়ার্ক এবং RPC সার্ভার উভয়ই রান করবে।
 * Usage: node mpoint-node.js [--port 53412] [--rpcport 8332] [--seed ip:port]
 */

const { NodeServer } = require('../../node/server.js');
const { RpcServer } = require('../../node/rpc/rpc-server.js');

// Parse basic command line arguments manually (Zero dependencies!)
const args = process.argv.slice(2);
let p2pPort = 53412; // Mpoint default P2P port
let rpcPort = 8332;  // Default RPC port
const seeds = [];

for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) p2pPort = parseInt(args[++i]);
    if (args[i] === '--rpcport' && args[i + 1]) rpcPort = parseInt(args[++i]);
    if (args[i] === '--seed' && args[i + 1]) seeds.push(args[++i]);
}

async function start() {
    console.log("=========================================");
    console.log("   MPOINT DECENTRALIZED NODE v1.0.0      ");
    console.log("=========================================\n");

    const node = new NodeServer(p2pPort);
    const rpc = new RpcServer(node, rpcPort);

    await node.start();
    await rpc.start();

    // Connect to seed nodes if provided
    for (const seed of seeds) {
        const [host, portStr] = seed.split(':');
        const port = portStr ? parseInt(portStr) : 53412;
        node.connectToPeer(host, port);
    }
    
    console.log("\nNode is fully operational. Press Ctrl+C to exit.");
}

start().catch(console.error);
