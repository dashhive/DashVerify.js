const LITTLE_ENDIAN = true;
const MAX_U16 = -1 + Math.pow(2, 16);
const MAX_U32 = -1 + Math.pow(2, 32);

let DashMessage = {};

DashMessage.utils = {};

DashMessage.utils.textEncoder = new TextEncoder();

/**
 * Decode Standard or URL-safe Base64 to a Uint8Array
 * @param {Base64} base64
 * @returns {Uint8Array}
 */
DashMessage.utils.base64ToBytes = function (base64) {
  let rfcBase64 = DashMessage.utils.urlBase64ToRfcBase64(base64);
  let bytes = DashMessage.utils.rfcBase64ToBytes(rfcBase64);
  return bytes;
};

/**
 * Decode RFC Base64 to a Uint8Array
 * @param {RFCBase64} rfcBase64
 * @returns {Uint8Array}
 */
DashMessage.utils.rfcBase64ToBytes = function (rfcBase64) {
  let binstr = atob(rfcBase64);
  let bytes = new Uint8Array(binstr.length);
  for (let i = 0; i < binstr.length; i += 1) {
    bytes[i] = binstr.charCodeAt(i);
  }

  return bytes;
};

/**
 * Recode URL-safe Base64 to a RFC Base64
 * @param {URLBase64} urlBase64
 * @returns {RFCBase64}
 */
DashMessage.utils.urlBase64ToRfcBase64 = function (urlBase64) {
  let rfcBase64 = urlBase64.replace(/_/g, "/");
  rfcBase64 = rfcBase64.replace(/-/g, "+");
  while (rfcBase64.length % 4 > 0) {
    rfcBase64 += "=";
  }

  return rfcBase64;
};

/**
 * Encode Uint8Array bytes as Standard Base64
 * @param {Uint8Array} bytes
 * @returns {RFCBase64}
 */
DashMessage.utils.bytesToRfcBase64 = function (bytes) {
  //@ts-ignore - trust me bro
  let binaryString = String.fromCharCode.apply(null, bytes);

  let base64 = btoa(binaryString);
  return base64;
};

/**
 * @param {Uint8Array} bytes
 * @returns {Promise<Uint8Array>}
 */
DashMessage.utils.doubleSha256 = async function (bytes) {
  let Crypto = globalThis.crypto;

  let ab = await Crypto.subtle.digest({ name: "SHA-256" }, bytes);
  ab = await Crypto.subtle.digest({ name: "SHA-256" }, ab);

  let hashBytes = new Uint8Array(ab);
  return hashBytes;
};

/**
 * @param {Array<Uint8Array>} bytesList
 * @param {Number} [totalLen]
 * @returns {Uint8Array}
 */
DashMessage.utils.concatBytes = function (bytesList, totalLen = 0) {
  if (totalLen === 0) {
    for (let i = 0; i < bytesList.length; i += 1) {
      totalLen += bytesList[i].length;
    }
  }

  let totalBytes = new Uint8Array(totalLen);

  let offset = 0;
  for (let i = 0; i < bytesList.length; i += 1) {
    let bytes = bytesList[i];
    totalBytes.set(bytes, offset);
    offset += bytes.length;
  }

  return totalBytes;
};

/**
 * @param {Number} n
 */
DashMessage.utils.toVarInt32 = function (n) {
  if (n < 253) {
    let bytes = Uint8Array.from([n]);
    return bytes;
  }

  if (n <= MAX_U16) {
    let bytes = new Uint8Array(1 + 2);
    let dv = new DataView(bytes.buffer);

    let offset = 0;
    bytes[offset] = 253;

    offset += 1;
    dv.setUint16(offset, n, LITTLE_ENDIAN);

    return bytes;
  }

  if (n <= MAX_U32) {
    let bytes = new Uint8Array(1 + 4);
    let dv = new DataView(bytes.buffer);

    let offset = 0;
    bytes[offset] = 254;

    offset += 1;
    dv.setUint32(offset, n, LITTLE_ENDIAN);

    return bytes;
  }

  throw new Error(
    `nobody is signing multi-gigabyte messages and, if they are, they need to stop`,
  );
};

DashMessage.DASH_MAGIC_BYTES = DashMessage.utils.textEncoder.encode(
  "DarkCoin Signed Message:\n",
);

/**
 * @callback Signer
 * @param {Uint8Array} hashBytes
 * @param {Uint8Array} privkeyBytes
 */

/**
 * Hashes the message to the scopes of the given network and adds the recovery byte
 * @param {Uint8Array} privkeyBytes
 * @param {Uint8Array} msgBytes
 * @param {Signer} fnSign
 * @param {Uint8Array} [magicBytes] - the magic network/coin bytes
 */
DashMessage.magicSign = async function (
  privkeyBytes,
  msgBytes,
  fnSign,
  magicBytes = DashMessage.DASH_MAGIC_BYTES,
) {
  let hashBytes = await DashMessage.magicHash(msgBytes, magicBytes);

  let signature = await fnSign(privkeyBytes, hashBytes);
  let recoverySigBytes = DashMessage.encodeRecoverySig(signature);

  return recoverySigBytes;
};

/**
 * @typedef Signature
 * @prop {Uint8Array} bytes
 * @prop {Bit} recovery - 0 or 1
 * @prop {Boolean} compressed
 */

/**
 * adds the recovery byte to the signature
 * @param {Signature} signature
 */
DashMessage.encodeRecoverySig = function (signature) {
  let recoverySigBytes = new Uint8Array(65);

  // +27 because reasons
  // +4 for compressed
  let recoveryByte = 27 + 4;
  recoveryByte += signature.recovery;

  recoverySigBytes[0] = recoveryByte;
  recoverySigBytes.set(signature.bytes, 1);

  return recoverySigBytes;
};

/**
 * @callback PubKeyHasher
 * @param {Uint8Array} pubkeyBytes
 * @returns {Promise<Uint8Array>} - pubKeyHash
 */

/**
 * @param {Uint8Array} pkhBytes - the decoded address (pubKeyHash)
 * @param {Uint8Array} msgBytes
 * @param {Uint8Array} recoverySigBytes - the magic signature (includes recovery byte)
 * @param {Recoverer} fnRecoverPublicKey - the secp256k1 recoverPublicKey function to use
 * @param {PubKeyHasher} fnPubkeyToPkh - the double sh256 ripemd160 function
 * @param {Uint8Array} [magicBytes] - the magic network/coin bytes
 */
DashMessage.magicVerify = async function (
  pkhBytes,
  msgBytes,
  recoverySigBytes,
  fnRecoverPublicKey,
  fnPubkeyToPkh,
  magicBytes = DashMessage.DASH_MAGIC_BYTES,
) {
  let pubkeyBytes = await DashMessage.magicRecoverPubkey(
    msgBytes,
    recoverySigBytes,
    fnRecoverPublicKey,
    magicBytes,
  );
  let signerPkh = await fnPubkeyToPkh(pubkeyBytes);

  let equal = DashMessage._areHashesEqual(signerPkh, pkhBytes);
  return equal;
};

DashMessage._doubleHash = DashMessage.utils.doubleSha256;

/**
 * @param {Uint8Array} msgBytes
 * @param {Uint8Array} [magicBytes] - the magic network/coin bytes
 */
DashMessage.magicHash = async function (
  msgBytes,
  magicBytes = DashMessage.DASH_MAGIC_BYTES,
) {
  let bytes = DashMessage._magicConcat(magicBytes, msgBytes);
  let hashBytes = DashMessage._doubleHash(bytes);
  return hashBytes;
};

/**
 * @param {Uint8Array} magicBytes - the magic network/coin bytes
 * @param {Uint8Array} msgBytes
 */
DashMessage._magicConcat = function (magicBytes, msgBytes) {
  let magicVarSize = DashMessage.utils.toVarInt32(magicBytes.length);
  let msgVarSize = DashMessage.utils.toVarInt32(msgBytes.length);
  let totalLen =
    magicVarSize.length +
    magicBytes.length +
    msgVarSize.length +
    msgBytes.length;

  let bytes = DashMessage.utils.concatBytes(
    [magicVarSize, magicBytes, msgVarSize, msgBytes],
    totalLen,
  );

  return bytes;
};

/**
 * Safe to check equality of hashes, but not raw secure values
 * (not due to lack of security, but because timing-safeness may get JITed away)
 * @param {Uint8Array|Array<Number>} a
 * @param {Uint8Array|Array<Number>} b
 * @return {Boolean}
 */
DashMessage._areHashesEqual = function (a, b) {
  if (a.length !== b.length) {
    return false;
  }

  // note: this would be timing safe, but the JIT
  //       optimizer will sometimes defeat that.
  let isEqual = true;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      isEqual = false;
    }
  }

  return isEqual;
};

/**
 * @param {Uint8Array} recoverySigBytes - the magic signature (includes recovery byte)
 */
DashMessage.decodeRecoverySig = function (recoverySigBytes) {
  // https://en.bitcoin.it/wiki/Message_signing
  // Else, if HeaderByte is between 31 and 34 inclusive, use "ECDSA verification, P2PKH compressed address". [sic]
  let magicRecoveryOffset = 27 + 4;

  let signature = {
    compressed: true,
    recovery: recoverySigBytes[0] - magicRecoveryOffset,
    bytes: recoverySigBytes.subarray(1),
  };
  return signature;
};

/**
 * @callback Recoverer
 * @param {Uint8Array} hashBytes - message hash (the magic hash of the message)
 * @param {Uint8Array} sigBytes - decoded (non-magic) signature
 * @param {UInt8} recovery - decoded from the magic signature
 * @param {Boolean} [isCompressed] - always true
 * @returns {Promise<Uint8Array>} - pubkey
 */

/**
 * @param {Uint8Array} msgBytes
 * @param {Uint8Array} recoverySigBytes - the magic signature (includes recovery byte)
 * @param {Recoverer} fnRecoverPublicKey - the secp256k1 recoverPublicKey function to use
 * @param {Uint8Array} [magicBytes] - the magic network/coin bytes
 * @returns {Promise<Uint8Array>} - public key bytes
 */
DashMessage.magicRecoverPubkey = async function (
  msgBytes,
  recoverySigBytes,
  fnRecoverPublicKey,
  magicBytes = DashMessage.DASH_MAGIC_BYTES,
) {
  let magicHash = await DashMessage.magicHash(msgBytes, magicBytes);
  let signature = DashMessage.decodeRecoverySig(recoverySigBytes);
  let pubkeyBytes = await fnRecoverPublicKey(
    magicHash,
    signature.bytes,
    signature.recovery,
    signature.compressed,
  );
  return pubkeyBytes;
};

/** @typedef {Number} Bit */
/** @typedef {Number} UInt8 */
/** @typedef {String} Base58Check */
/** @typedef {String} Base64 */
/** @typedef {String} RFCBase64 */
/** @typedef {String} URLBase64 */

export default DashMessage;
