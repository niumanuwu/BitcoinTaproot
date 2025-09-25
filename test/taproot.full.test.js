// test/taproot.full.test.js
const { expect } = require('chai');
const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
bitcoin.initEccLib(ecc);

const {
  createTaprootAddress,
  computeControlBlockForIndex,
  tweakPrivateKey,
  depositToAddress,
  buildAndBroadcastScriptPathSpend,
  spendCltvLeaf,
  spendKeyPath
} = require('../src/service');

const { createRpcClient } = require('../src/rpc');

function rand32() { return Buffer.from(bitcoin.crypto.randomBytes(32)); }

describe('Full Taproot flows (regtest) - end-to-end', function() {
  this.timeout(120000);
  const rpc = createRpcClient();

  let privKeys = []; // raw 32B buffers (for pub keys used in leaf scripts)
  let pubCompressed = []; // compressed 33B pubkeys (for internal)
  let info; // taprootInfo
  let utxoForScriptPath;
  let utxoForCltv;
  let utxoForKeyPath;
  let network = bitcoin.networks.regtest;

  before(async () => {
    // ensure there are spendable coins in node wallet
    await rpc.generate(101);

    // generate 3 signing keypairs (these are used in leaf scripts)
    for (let i = 0; i < 3; i++) {
      const priv = rand32();
      privKeys.push(priv);
      const pub = ecc.pointFromScalar(priv, true); // compressed 33B
      pubCompressed.push(Buffer.from(pub));
    }

    // We'll use privKeys[0]'s pub as internal key for demo (again - in prod use separate internal key)
    const height = await rpc.getBlockCount();
    info = createTaprootAddress(pubCompressed, height, network, 6); // 6-block lock for demo

    // FUND 3 separate UTXOs (one for each spend) for clarity
    // Fund for script-path spend:
    const deposit1 = await depositToAddress(rpc, info.address, 1.0);
    utxoForScriptPath = { txid: deposit1.txid, vout: deposit1.voutIndex, value: deposit1.valueSats };

    // Fund for CLTV spend:
    const deposit2 = await depositToAddress(rpc, info.address, 1.0);
    utxoForCltv = { txid: deposit2.txid, vout: deposit2.voutIndex, value: deposit2.valueSats };

    // Fund for key-path spend:
    const deposit3 = await depositToAddress(rpc, info.address, 1.0);
    utxoForKeyPath = { txid: deposit3.txid, vout: deposit3.voutIndex, value: deposit3.valueSats };
  });

  it('builds and broadcasts a valid 2-of-3 script-path spend', async () => {
    // compute control block for leaf 0 (2-of-3)
    const ctrl = computeControlBlockForIndex(info.internalPubkeyFull, info.leaves, 0);

    // Build transaction skeleton and compute sighashes for signers 0 and 1
    // We'll create a tx for signing by both signers: we will compute the sighash and sign them individually.
    const tx = new bitcoin.Transaction();
    tx.version = 2;
    tx.addInput(Buffer.from(utxoForScriptPath.txid, 'hex').reverse(), utxoForScriptPath.vout, 0xffffffff);
    const dest = await rpc.getNewAddress();
    tx.addOutput(bitcoin.address.toOutputScript(dest, network), utxoForScriptPath.value - 500);

    const sighash = tx.hashForWitnessV1(0, [info.leaves[0]], [utxoForScriptPath.value], bitcoin.Transaction.SIGHASH_DEFAULT);

    const sig0 = Buffer.from(ecc.signSchnorr(sighash, privKeys[0]));
    const sig1 = Buffer.from(ecc.signSchnorr(sighash, privKeys[1]));

    const txid = await buildAndBroadcastScriptPathSpend(rpc, utxoForScriptPath, info, 0, [sig0, sig1], dest, 500, network);
    await rpc.generate(1);
    const txInfo = await rpc.getTransaction(txid);
    expect(txInfo.confirmations).to.be.at.least(1);
  });

  it('builds and broadcasts a valid CLTV script-path spend after lock', async () => {
    // Wait until lockHeight satisfied: mine enough blocks
    const current = await rpc.getBlockCount();
    const blocksToMine = Math.max(0, info.lockHeight - current + 1);
    if (blocksToMine > 0) await rpc.generate(blocksToMine);

    // sign CLTV leaf using privKeys[0]
    const dest = await rpc.getNewAddress();
    const txid = await spendCltvLeaf(rpc, utxoForCltv, info, privKeys[0], dest, 500, network);
    await rpc.generate(1);
    const txInfo = await rpc.getTransaction(txid);
    expect(txInfo.confirmations).to.be.at.least(1);
  });

  it('builds and broadcasts a valid key-path spend (tweaked internal key)', async () => {
    // Use internal private key equal to privKeys[0] (since we used that as internal earlier)
    const internalPriv = privKeys[0];

    const dest = await rpc.getNewAddress();
    const txid = await spendKeyPath(rpc, utxoForKeyPath, internalPriv, info, dest, 500, network);
    await rpc.generate(1);
    const txInfo = await rpc.getTransaction(txid);
    expect(txInfo.confirmations).to.be.at.least(1);
  });
});
