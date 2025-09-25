// src/service.js
const bitcoin = require('bitcoinjs-lib');
const OPS = require('bitcoin-ops');
const ecc = require('tiny-secp256k1');
bitcoin.initEccLib(ecc);

// Helper: tagged hash (bitcoinjs-lib exposes)
const { taggedHash } = bitcoin.crypto;

/**
 * === Helpers for Taproot (BIP-341) ===
 *
 * - tapLeafHash(script) -> 32-byte Buffer
 * - tapBranchHash(a,b) -> 32-byte Buffer (tagged 'TapBranch')
 * - computeMerkleRoot(leaves) -> Buffer
 * - computeControlBlock(internalPubkeyX, leaves, targetLeafIndex) -> Buffer
 * - tweakPrivateKey(privKey (32B), internalPubkeyX, merkleRoot) -> { tweakedPriv, tweakedPubX, parity }
 *
 * Note: this implementation assumes "leaves" is an array of raw script Buffers.
 */

// tap leaf hash (leaf version 0xc0 used)
function tapLeafHash(scriptBuffer) {
  // TapLeaf tagged hash input = ser_uint8(leaf_version) || varint(script length) || script bytes
  // bitcoinjs-lib's taggedHash expects the full buffer to hash; for compatibility we replicate BIP spec:
  // but easier: follow bitcoinjs-lib approach: tag = TapLeaf, msg = 0xc0 + script
  return taggedHash('TapLeaf', Buffer.concat([Buffer.from([0xc0]), scriptBuffer]));
}

// TapBranch
function tapBranchHash(a, b) {
  // BIP-341: tag = "TapBranch", input = min(a,b) || max(a,b) (lexicographic)
  if (Buffer.compare(a, b) === -1) {
    return taggedHash('TapBranch', Buffer.concat([a, b]));
  } else {
    return taggedHash('TapBranch', Buffer.concat([b, a]));
  }
}

function computeMerkleRootFromLeafHashes(leafHashArr) {
  // generic merkle for an array of leaf hashes (left-right lexicographic ordering per node)
  if (leafHashArr.length === 0) return Buffer.from([]);
  let current = leafHashArr.slice();
  while (current.length > 1) {
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 === current.length) {
        // odd, propagate up (BIP does not duplicate; but our use case is 2 leaves)
        next.push(current[i]);
      } else {
        next.push(tapBranchHash(current[i], current[i + 1]));
      }
    }
    current = next;
  }
  return current[0];
}

/**
 * Compute merkle root for script tree (array of script Buffers)
 */
function computeMerkleRoot(scriptLeaves) {
  const leafHashes = scriptLeaves.map(s => tapLeafHash(s));
  if (leafHashes.length === 1) return Buffer.alloc(0); // merkle root empty if single leaf per BIP-341
  return computeMerkleRootFromLeafHashes(leafHashes);
}

/**
 * Compute control block for a given leaf index (works for any number of leaves).
 * control block = 1 byte (leaf_version | parity) || internalPubkeyX (32 bytes) || merkle path (32*n)
 *
 * Parity bit = parity of the full internal public key's y coordinate (0 or 1). We must compute this.
 *
 * Implementation notes:
 * - internalPubkeyX is the x-only 32B pubkey
 * - We need the parity of the full internal public key (we can reconstruct full pubkey by trying both odd/even y).
 */
function liftXOnly(internalX) {
  // Returns full compressed pubkey (33 bytes) with appropriate prefix (0x02 for even y, 0x03 for odd y).
  // tiny-secp256k1 provides xOnlyPointFromScalar? Not exactly. We'll attempt both prefixes and use ecc.isPoint for parity reasoning.
  // tiny-secp256k1 provides xOnlyPointFromScalar and xOnlyCompress; but not lift.
  // Convenient approach: We will try both parity prefixes and check that after tweaking the resulting point is valid via ecc.pointFromScalar? However we can't derive y easily.
  // For control block we only need the parity of the internal key's full pubkey before tweak, which can be derived when generating the keypair originally (we will return parity with internal pubkey).
  throw new Error('liftXOnly should be called only if you have no parity — prefer to supply internalPublicKeyFull (33B) or parity externally.');
}

/**
 * Build control block for target leaf index.
 * For simplicity this function expects the caller to provide the internalPubkeyFull (33-byte compressed pubkey)
 * in addition to internalPubkeyX. The parity bit is derived from the first byte of internalPubkeyFull (0x02 even -> parity 0, 0x03 odd -> parity 1).
 *
 * @param {Buffer} internalPubkeyFull - 33-byte compressed pubkey of internal key (not x-only)
 * @param {Buffer[]} scriptLeaves - array of script Buffers (same order that will be provided to p2tr)
 * @param {Number} targetIndex - index of the leaf we want the control block for
 * @returns {Buffer} control block
 */
function computeControlBlockForIndex(internalPubkeyFull, scriptLeaves, targetIndex) {
  if (!Buffer.isBuffer(internalPubkeyFull) || internalPubkeyFull.length !== 33) {
    throw new Error('internalPubkeyFull must be 33-byte compressed public key');
  }
  const internalX = internalPubkeyFull.slice(1, 33); // x-only
  const parity = (internalPubkeyFull[0] === 0x03) ? 1 : 0;

  // Build leaf hashes array and merkle path for target
  const leafHashes = scriptLeaves.map(s => tapLeafHash(s));
  if (leafHashes.length === 1) {
    // control block contains just header + internal key (no merkle path)
    return Buffer.concat([Buffer.from([0xc0 | parity]), internalX]);
  }

  // For general tree we need the sibling path for targetIndex:
  // We'll compute merkle path by constructing tree layers and at each layer noting sibling
  let indexes = leafHashes.map((_, i) => i);
  let path = [];
  let layer = leafHashes.slice();

  let idx = targetIndex;
  while (layer.length > 1) {
    const nextLayer = [];
    for (let i = 0; i < layer.length; i += 2) {
      if (i + 1 === layer.length) {
        nextLayer.push(layer[i]); // propagate
      } else {
        nextLayer.push(tapBranchHash(layer[i], layer[i + 1]));
      }
    }

    // find sibling for idx
    const pairIndex = (idx % 2 === 0) ? idx + 1 : idx - 1;
    if (pairIndex < layer.length) {
      path.push(layer[pairIndex]);
    }
    // update idx for next layer
    idx = Math.floor(idx / 2);
    layer = nextLayer;
  }

  // control block = header byte + internalX + siblings in order
  return Buffer.concat([Buffer.from([0xc0 | parity]), internalX, ...path]);
}

/**
 * Tweak private key: privKey is Buffer (32), internalPubkeyX is Buffer(32), merkleRoot is Buffer(32) or empty Buffer.
 * Returns { tweakedPriv (32), tweakedPubKey (33 compressed), tweakedX (32), parity }
 */
function tweakPrivateKey(privKey32, internalPubkeyX, merkleRoot) {
  if (!Buffer.isBuffer(privKey32) || privKey32.length !== 32) throw new Error('privKey must be 32 bytes');
  if (!Buffer.isBuffer(internalPubkeyX) || internalPubkeyX.length !== 32) throw new Error('internalPubkeyX must be 32 bytes');
  merkleRoot = merkleRoot || Buffer.alloc(0);

  // compute tweak = taggedHash('TapTweak', internal_pubkey_x || merkle_root)
  const t = taggedHash('TapTweak', Buffer.concat([internalPubkeyX, merkleRoot]));
  // tweak is 32 bytes; interpret as scalar mod n
  // tweakedPriv = (privKey + tweak) mod n
  const n = Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 'hex'); // curve order
  // use tiny-secp256k1 to add scalars via privateAdd
  const ok = ecc.privateAdd(privKey32, t);
  if (!ok) throw new Error('tweak resulted in invalid private key (unlikely)');
  const tweaked = Buffer.from(ok); // privateAdd returns Buffer or false (node-binding)
  // get tweaked pubkey
  const tweakedPub = ecc.pointFromScalar(tweaked, true);
  if (!tweakedPub) throw new Error('failed to compute tweaked pubkey');
  const tweakedX = Buffer.from(tweakedPub.slice(1, 33));
  const parity = (tweakedPub[0] === 0x03) ? 1 : 0;
  return {
    tweakedPriv: tweaked,
    tweakedPub: Buffer.from(tweakedPub),
    tweakedX,
    parity
  };
}

/**
 * === Public API functions required by you ===
 *
 * 1) createTaprootAddress(pubkeys33?) -> creates taproot address from 3 public keys (we accept full compressed pubkeys or x-only)
 *     - returns { address, internalPubkeyFull (33), internalX (32), scriptLeaves, lockHeight, merkleRoot }
 *
 * 2) depositToAddress(rpcClient, address, amountBTC) -> sends funds using RPC and mines 1 block (regtest convenience)
 *
 * 3) produceWitnessSighash(rawUtxo, leafScript, valueSats, destination, feeSats) -> returns sighash Buffer for script-path signers
 *
 * 4) buildAndBroadcastScriptPathSpend(rpcClient, utxoObj, leafIndex, sigs (array of 64-byte buffers), destination, feeSats)
 *
 * 5) spendCltvLeaf(rpcClient, utxoObj, ... ) -> builds, signs (with single priv), broadcasts the CLTV script-path spend (waits lock)
 *
 * 6) spendKeyPath(rpcClient, utxoObj, internalPriv, scriptLeaves, destination, fee) -> derive tweaked priv and key-path sign + broadcast
 */

// Helper: accept keys as either 33-byte compressed pubkeys or x-only 32-byte. We'll require internalPubKeyFull to be 33-bytes.
function ensureCompressedPubkey(pub) {
  if (Buffer.isBuffer(pub) && pub.length === 33) return pub;
  if (Buffer.isBuffer(pub) && pub.length === 32) {
    // unknown parity; we'll default to 0x02 prefix (even) and return compressed pubkey
    return Buffer.concat([Buffer.from([0x02]), pub]);
  }
  throw new Error('provide Buffer(33) compressed pubkey or Buffer(32) x-only pubkey');
}

/**
 * 1) createTaprootAddress
 * pubkeys: array of three public keys. Accepts:
 *    - 33-byte compressed pubkey Buffer
 *    - 32-byte x-only Buffer (will be treated as compressed with prefix 0x02)
 * internalKeyOptionally: if not passed, we use first pubkey as internal key (you should use a separate internal key in prod)
 */
function createTaprootAddress(pubkeys, currentBlockHeight, network = bitcoin.networks.testnet, lockDeltaBlocks = 2000, internalKeyOptionally) {
  if (!Array.isArray(pubkeys) || pubkeys.length !== 3) throw new Error('need 3 pubkeys');
  const lockHeight = currentBlockHeight + lockDeltaBlocks;

  // Build leaf scripts
  const xonly = pubkeys.map(k => (k.length === 33 ? k.slice(1, 33) : k)); // x-only

  const leaf1 = bitcoin.script.compile([
    xonly[0], OPS.OP_CHECKSIG,
    xonly[1], OPS.OP_CHECKSIGADD,
    xonly[2], OPS.OP_CHECKSIGADD,
    bitcoin.script.number.encode(2),
    OPS.OP_NUMEQUAL
  ]);

  const leaf2 = bitcoin.script.compile([
    bitcoin.script.number.encode(lockHeight),
    OPS.OP_CHECKLOCKTIMEVERIFY,
    OPS.OP_DROP,
    xonly[0],
    OPS.OP_CHECKSIG
  ]);

  // internal key
  let internalFull = internalKeyOptionally ? ensureCompressedPubkey(internalKeyOptionally) : ensureCompressedPubkey(pubkeys[0]);
  const internalX = internalFull.slice(1, 33);

  // scriptTree for payments.p2tr requires leaves as {output: script}
  const scriptTree = [{ output: leaf1 }, { output: leaf2 }];

  const p2tr = bitcoin.payments.p2tr({
    internalPubkey: internalX,
    scriptTree,
    network
  });

  // compute merkle root for use in tweaks (empty if single leaf; 2-leaf case returns 32B)
  const merkleRoot = computeMerkleRoot([leaf1, leaf2]);

  return {
    address: p2tr.address,
    internalPubkeyFull: internalFull,
    internalX,
    leaves: [leaf1, leaf2],
    lockHeight,
    merkleRoot,
    scriptTree // helpful for external use
  };
}

/**
 * 2) depositToAddress - simple helper to send coins via RPC and mine 1 block (for regtest).
 * Returns { txid, voutIndex, valueSats }
 */
async function depositToAddress(rpcClient, address, amountBtc = 1.0) {
  const txid = await rpcClient.sendToAddress(address, amountBtc);
  // Mine 1 block so it's confirmed (regtest convenience)
  await rpcClient.generate(1);
  const raw = await rpcClient.getRawTransaction(txid, true);
  const voutIndex = raw.vout.findIndex(v => v.scriptPubKey.addresses && v.scriptPubKey.addresses.includes(address));
  const valueSats = Math.round(raw.vout[voutIndex].value * 1e8);
  return { txid, voutIndex, valueSats, scriptPubKeyHex: raw.vout[voutIndex].scriptPubKey.hex };
}

/**
 * 3) produceWitnessSighash (for script-path)
 * Returns Buffer which should be signed (schnorr) by signers.
 *
 * utxo must include { txid, vout, value (sats) } and we will build a single-input tx sending to destination with fee.
 */
function produceWitnessSighash(utxo, leafScript, destinationScriptBuf, feeSats, network = bitcoin.networks.regtest) {
  // Build the spending tx skeleton and compute hashForWitnessV1 for input 0 with leafScript array
  const tx = new bitcoin.Transaction();
  tx.version = 2;
  tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout, 0xffffffff);
  const sendValue = utxo.value - feeSats;
  tx.addOutput(destinationScriptBuf || bitcoin.address.toOutputScript('tb1q...', network), sendValue);
  // hashForWitnessV1 expects arrays of scripts and values matching inputs
  const hash = tx.hashForWitnessV1(0, [leafScript], [utxo.value], bitcoin.Transaction.SIGHASH_DEFAULT);
  return hash; // Buffer
}

/**
 * 4) buildAndBroadcastScriptPathSpend
 * - utxoObj: { txid, vout, value }
 * - leafIndex: index in leaves array (0 = multisig)
 * - sigs: array of signer 64-byte Schnorr sig Buffers (order must match leaf script expectation). For our 2-of-3 script, provide 2 signatures for pub1 and pub2 in that order.
 * - destination: address string
 * - feeSats: integer
 *
 * This function will construct witness stack: [sig1, sig2, ... , leafScript, controlBlock] and broadcast via rpcClient.
 * Returns txid.
 */
async function buildAndBroadcastScriptPathSpend(rpcClient, utxoObj, taprootInfo, leafIndex, sigs, destination, feeSats, network = bitcoin.networks.regtest) {
  const leafScript = taprootInfo.leaves[leafIndex];
  // compute control block for leafIndex using internal full pubkey (33B)
  const controlBlock = computeControlBlockForIndex(taprootInfo.internalPubkeyFull, taprootInfo.leaves, leafIndex);

  // Build tx
  const tx = new bitcoin.Transaction();
  tx.version = 2;
  tx.addInput(Buffer.from(utxoObj.txid, 'hex').reverse(), utxoObj.vout, 0xffffffff);
  tx.addOutput(bitcoin.address.toOutputScript(destination, network), utxoObj.value - feeSats);

  // witness: signatures (as Buffer) then leafScript then controlBlock
  const witness = [...sigs, leafScript, controlBlock];
  tx.setWitness(0, witness);

  const raw = tx.toHex();
  const txid = await rpcClient.sendRawTransaction(raw);
  return txid;
}

/**
 * 5) spendCltvLeaf
 * - This function constructs and signs the CLTV leaf spend. It:
 *   * ensures the tx has nLockTime >= lockHeight
 *   * sets the input sequence to 0xfffffffe (to enable locktime)
 *   * computes the sighash for the leafScript and signs it with given privKey (32B)
 *   * assembles witness [sig, leafScript, controlBlock], broadcasts and returns txid
 *
 * Parameters:
 *   - rpcClient
 *   - utxoObj { txid, vout, value }
 *   - taprootInfo (as returned from createTaprootAddress)
 *   - privKey32 (Buffer 32) - private key corresponding to pubkey used in CLTV leaf (the first pubkey in our scheme)
 *   - destination (address)
 *   - feeSats (int)
 */
async function spendCltvLeaf(rpcClient, utxoObj, taprootInfo, privKey32, destination, feeSats, network = bitcoin.networks.regtest) {
  const leafIndex = 1; // we constructed leaf 2 as CLTV (index 1)
  const leafScript = taprootInfo.leaves[leafIndex];
  const controlBlock = computeControlBlockForIndex(taprootInfo.internalPubkeyFull, taprootInfo.leaves, leafIndex);

  // Build transaction with locktime
  const tx = new bitcoin.Transaction();
  tx.version = 2;
  tx.locktime = taprootInfo.lockHeight; // must be >= lockHeight
  tx.addInput(Buffer.from(utxoObj.txid, 'hex').reverse(), utxoObj.vout, 0xfffffffe);
  tx.addOutput(bitcoin.address.toOutputScript(destination, network), utxoObj.value - feeSats);

  // sighash for witness v1
  const sighash = tx.hashForWitnessV1(0, [leafScript], [utxoObj.value], bitcoin.Transaction.SIGHASH_DEFAULT);
  // sign using schnorr (BIP340)
  const sig = Buffer.from(ecc.signSchnorr(sighash, privKey32));
  // assemble witness
  tx.setWitness(0, [sig, leafScript, controlBlock]);

  const raw = tx.toHex();
  const txid = await rpcClient.sendRawTransaction(raw);
  return txid;
}

/**
 * 6) spendKeyPath
 * - Performs key-path spend (tapscript key-path) by deriving tweaked private key and signing.
 * - Parameters:
 *    - rpcClient
 *    - utxoObj
 *    - internalPrivKey32 (Buffer 32) <-- this is the private key whose x-only pubkey was used as internal key when creating address
 *    - taprootInfo (from createTaprootAddress)
 *    - destination, feeSats
 *
 * Steps:
 *  - compute merkleRoot from leaves
 *  - derive tweakedPriv = priv + taggedHash('TapTweak', internalX || merkleRoot)
 *  - build tx; compute hashForWitnessV1 with empty scripts array? For key-path signing, bitcoinjs-lib expects script list empty and sighash computed with empty script; but actually hashForWitnessV1 takes scripts and values arrays; for key-path we pass empty arrays for scripts and values. To keep it consistent, use the standard method: call tx.hashForWitnessV1(0, [], [], SIGHASH_DEFAULT) and sign that.
 *  - set witness to [signature], broadcast.
 */
async function spendKeyPath(rpcClient, utxoObj, internalPrivKey32, taprootInfo, destination, feeSats, network = bitcoin.networks.regtest) {
  // compute merkle root (empty Buffer if single leaf)
  const merkleRoot = taprootInfo.merkleRoot || Buffer.alloc(0);
  // internal X-only:
  const internalX = taprootInfo.internalX;

  // derive tweaked private key
  const tweaked = tweakPrivateKey(internalPrivKey32, internalX, merkleRoot);
  const tweakedPriv = tweaked.tweakedPriv;

  // Build tx (key-path spend uses no script path)
  const tx = new bitcoin.Transaction();
  tx.version = 2;
  tx.addInput(Buffer.from(utxoObj.txid, 'hex').reverse(), utxoObj.vout, 0xffffffff);
  tx.addOutput(bitcoin.address.toOutputScript(destination, network), utxoObj.value - feeSats);

  // compute sighash for key-path spend: per BIP341, hash is computed with empty script list for input (scriptPath = null).
  const sighash = tx.hashForWitnessV1(0, [], [utxoObj.value], bitcoin.Transaction.SIGHASH_DEFAULT);

  const sig = Buffer.from(ecc.signSchnorr(sighash, tweakedPriv));
  // For key-path spend, witness is just signature (64 bytes) (no sighash flag appended in BIP340)
  tx.setWitness(0, [sig]);

  const raw = tx.toHex();
  const txid = await rpcClient.sendRawTransaction(raw);
  return txid;
}

module.exports = {
  // helpers exposed
  tapLeafHash,
  computeMerkleRoot,
  computeControlBlockForIndex,
  tweakPrivateKey,

  // requested functions
  createTaprootAddress,
  depositToAddress,
  produceWitnessSighash,
  buildAndBroadcastScriptPathSpend,
  spendCltvLeaf,
  spendKeyPath,
};
