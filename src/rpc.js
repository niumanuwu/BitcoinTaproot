const Client = require('bitcoin-core');

function createRpcClient() {
  return new Client({
    network: 'regtest',
    username: process.env.RPC_USER || 'user',
    password: process.env.RPC_PASS || 'pass',
    host: process.env.RPC_HOST || '127.0.0.1',
    port: process.env.RPC_PORT ? parseInt(process.env.RPC_PORT) : 18443
  });
}

module.exports = { createRpcClient };