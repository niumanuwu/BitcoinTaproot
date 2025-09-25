// Import all functions
const {
  createTaprootAddress,
  depositToAddress,
  produceWitnessSighash,
  buildAndBroadcastScriptPathSpend,
  spendCltvLeaf,
  spendKeyPath
} = require("./service");

const bufferPubkey1 = Buffer.from("039d815fa419f816f701e80f6c4f50089fedf0e3d74efad96d9cdb5117930e61c0", "hex");
const bufferPubkey2 = Buffer.from("037eeedaa390967956b958e2ebf8dd93cfbf934c9e363a4b64d8e27500e6d0b6e1", "hex");
const bufferPubkey3 = Buffer.from("0316e90c4a02eb9957a8d06fad448c6784675b1db42aec74f68c62d55279b58f07", "hex");
const pubkey1 = "039d815fa419f816f701e80f6c4f50089fedf0e3d74efad96d9cdb5117930e61c0";
const pubkey2 = "037eeedaa390967956b958e2ebf8dd93cfbf934c9e363a4b64d8e27500e6d0b6e1";
const pubkey3 = "0316e90c4a02eb9957a8d06fad448c6784675b1db42aec74f68c62d55279b58f07";
const pubkeys = [pubkey1, pubkey2, pubkey3];

function validatePubkeyHex(pubkeyHex) {
  if (typeof pubkeyHex !== "string") {
    throw new Error("Pubkey must be a hex string");
  }
  if (!/^[0-9a-fA-F]+$/.test(pubkeyHex)) {
    throw new Error("Pubkey must be a valid hex string");
  }

  const pubkey = Buffer.from(pubkeyHex, "hex");

  // Compressed pubkey (33 bytes, prefix 0x02 or 0x03)
  if (pubkey.length === 33) {
    const prefix = pubkey[0];
    if (prefix !== 0x02 && prefix !== 0x03) {
      throw new Error("Invalid compressed pubkey prefix (must be 0x02 or 0x03)");
    }
    return pubkey; // ✅ return usable Buffer
  }

  // X-only pubkey (32 bytes)
  if (pubkey.length === 32) {
    return pubkey; // ✅ return usable Buffer
  }

  throw new Error("Invalid pubkey length (must be 32 or 33 bytes)");
}
