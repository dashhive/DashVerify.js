# [DashMessage.js](https://github.com/digitalcashdev/DashMessage.js)

_Electrum-Style Message Signing_ (a.k.a. _Satoshi-style Signing_), implemented
in JavaScript.

Used by the Dash network to Sign and Verify voting messages by DASH addresses.

```js
// JS
let equal = await DashMessage.magicVerify(addr, msg, recSig, verifyFn, pkhFn);
if (equal === true) {
  console.log("verified");
}
```

```sh
# Dev CLI
printf 'Hello, World!' | base64
# SGVsbG8sIFdvcmxkIQ==

./bin/dashmessage verify 'XyBmeuLa8y3D3XmzPvCTj5PVh7WvMPkLn1' 'SGVsbG8sIFdvcmxkIQ==' '<signature>'
```

# Table of Contents

- JS (Browser & Server)
  - Overview
  - Boilerplate
  - Sign
  - Verify
  - Utils
- Examples
  - [./examples/sign.js](/examples/sign.js)
  - [./examples/verify.js](/examples/verify.js)
  - [./bin/dashmessage](/bin/dashmessage)
  - [./tests/reciprocal.js](/tests/reciprocal.js)
- Dev CLI
  - Sign
  - Verify
- Spec

# JS

Works in Browsers, Node, and Bundlers.

```sh
npm install --save dashmessage@1.0
```

```js
// node versions < v24.0 may require `node --experimental-require-module`
let DashMessage = require(`dashmessage`);
```

## Overview

- Core (Sign, Verify, Hash, Recover)

  ```js
  await DashMessage.magicSign(privBytes, msgBytes, sign); // recSigBytes
  await DashMessage.magicVerify(pkh, msg, recSig, recoverPubkey, toPkh); // equal

  DashMessage.DASH_MAGIC_BYTES; // bytes for "DarkCoin Signed Message:\n"

  await DashMessage.magicHash(messageBytes, magicBytes); // hashBytes
  await DashMessage.magicRecoverPubkey(msg, recSig, recoverPubkey); // pubBytes
  DashMessage.encodeRecoverySig({ bytes, recovery, compressed }); // recSigBytes
  DashMessage.decodeRecoverySig(recoverySigBytes); // { bytes, recovery, compressed }
  ```
  (note: most of these have an optional `magicBytes` parameter)

- Convenience Utils (base64, etc)

  ```js
  DashMessage.utils.textEncoder.encode(str); // bytes
  DashMessage.utils.base64ToBytes(base64); // bytes
  DashMessage.utils.rfcBase64ToBytes(rfcBase64); // bytes
  DashMessage.utils.urlBase64ToRfcBase64(urlBase64); // urlBase64
  DashMessage.utils.bytesToRfcBase64(bytes); // rfcBase64

  await DashMessage.utils.doubleSha256(bytes); // hashBytes
  DashMessage.utils.concatBytes(bytesList, totalLen); // bytes
  DashMessage.utils.toVarInt32(n); // bytes
  ```

See [./bin/dashmessage](/bin/dashmessage) to see how the CLI is implemented.

## Boilerplate (you need this)

Here's some copy-pasta boilerplate that will **Just Work™**: \
(it's not "baked in" due to dependency management issues with some bundlers and
transpilers)

```js
import DashKeys from "dashkeys";
import Secp256k1 from "@dashincubator/secp256k1";

let boilerplate = {
  signMessage: async function (privkeyBytes, hashBytes) {
    let compressed = true;
    let [bytes, recovery] = await Secp256k1.sign(hashBytes, privkeyBytes, {
      extraEntropy: null, // for testing only, otherwise should be 'true'
      canonical: true,
      der: false,
      recovered: true,
    });
    return { bytes, compressed, recovery };
  },
  recoverPubkey: async function (msgHash, signature, recovery, isCompressed) {
    let pubkeyBytes = await Secp256k1.recoverPublicKey(
      msgHash,
      signature,
      recovery,
      isCompressed,
    );
    return pubkeyBytes;
  },
  toPubKeyHash: async function (pubkeyBytes) {
    let pkhBytes = await DashKeys.pubkeyToPkh(pubkeyBytes);
    return pkhBytes;
  },
};
```

## Signing

See the working example in [./examples/sign.js](/examples/sign.js).

```js
import DashKeys from "dashkeys";
import DashMessage from "dashmessage";

async function sign(wif, messageText) {
  let networkOpts = { version: "mainnet" };
  let privateKeyBytes = await DashKeys.wifToPrivKey(wif, networkOpts);
  let messageBytes = DashMessage.utils.textEncoder.encode(messageText);

  let recoverySigBytes = await DashMessage.magicSign(
    privateKeyBytes,
    messageBytes,
    boilerplate.signMessage,
    DashMessage.DASH_MAGIC_BYTES,
  );

  let sig = DashMessage.utils.bytesToRfcBase64(recoverySigBytes);
  return sig;
}

let messageText = "dte2022-akerdemelidis|estoever|mmason";
let wif = "XK5DHnAiSj6HQNsNcDkawd9qdp8UFMdYftdVZFuRreTMJtbJhk8i";

let sig = await sign(wif, messageText);
console.info(`Signature (base64):\n${sig}`);
// H2Opy9NX72iPZRcDVEHrFn2qmVwWMgc+DKILdVxl1yfmcL2qcpu9esw9wcD7RH0/dJHnIISe5j39EYahorWQM7I=
```

Note: you'll also need the _boilerplate_ functions in the section above.

## Verifying

See the working example in [./examples/verify.js](/examples/verify.js).

```js
import DashKeys from "dashkeys";
import DashMessage from "dashmessage";

async function mustVerify(address, messageText, sig) {
  let pkhBytes = await DashKeys.addrToPkh(address);
  let messageBytes = DashMessage.utils.textEncoder.encode(messageText);
  let recoverySigBytes = DashMessage.utils.base64ToBytes(sig);

  let isEqual = await DashMessage.magicVerify(
    pkhBytes,
    messageBytes,
    recoverySigBytes,
    boilerplate.recoverPubkey,
    boilerplate.pubkeyToPkh,
  );
  if (isEqual !== true) {
    throw new Error("invalid signature");
  }
}

let messageText = "dte2022-akerdemelidis|estoever|mmason";
let address = "XyBmeuLa8y3D3XmzPvCTj5PVh7WvMPkLn1";
let sig =
  "H2Opy9NX72iPZRcDVEHrFn2qmVwWMgc+DKILdVxl1yfmcL2qcpu9esw9wcD7RH0/dJHnIISe5j39EYahorWQM7I=";

await mustVerify(address, messageText, sig);

console.info(`verified`);
```

Note: you'll also need the _boilerplate_ functions above.

## Utils

Use `DashKeys` to convert between bytes and key formats - WIF (Private Key),
Address (PubKeyHash, PKH), Public Key, etc.

The built-in `Base64` utils are provided for working with Command Line and UI
tools.

# Dev CLI

These can be run from a local copy of the repo, but are not installed via npm.

```sh
git clone https://github.com/digitalcashdev/DashMessage.js
pushd ./DashMessage/

npm clean-install
```

## Signing

1. Create a WIF file containing the private key
   ```sh
   cat ./XyBmeuLa8y3D3XmzPvCTj5PVh7WvMPkLn1.wif
   # XK5DHnAiSj6HQNsNcDkawd9qdp8UFMdYftdVZFuRreTMJtbJhk8i
   ```
2. Encode the message as Base64 \
   (this is done as to allow for text or binary messages)
   ```sh
   printf 'dte2022-akerdemelidis|estoever|mmason' | base64
   ```
3. Sign the message
   ```sh
   ./bin/dashmessage sign \
       ./XyBmeuLa8y3D3XmzPvCTj5PVh7WvMPkLn1.wif \
       'ZHRlMjAyMi1ha2VyZGVtZWxpZGlzfGVzdG9ldmVyfG1tYXNvbg=='
   ```

Note: the random salt which would normally be used for ECDSA signatures is
turned off in the CLI as to match other tools in the ecosystem and to make for
easier testing. It's recommended to turn the extra entropy on in production.

## Verifying

1. Encode the message as Base64 \
   (this is done as to allow for text or binary messages)
   ```sh
   printf 'dte2022-akerdemelidis|estoever|mmason' | base64
   ```
2. Verify the message against the recovery signature
   ```sh
   ./bin/dashmessage verify \
       'XyBmeuLa8y3D3XmzPvCTj5PVh7WvMPkLn1' \
       'ZHRlMjAyMi1ha2VyZGVtZWxpZGlzfGVzdG9ldmVyfG1tYXNvbg==' \
       'H2Opy9NX72iPZRcDVEHrFn2qmVwWMgc+DKILdVxl1yfmcL2qcpu9esw9wcD7RH0/dJHnIISe5j39EYahorWQM7I='
   ```

# Specification

As of 2024 this bespoke message algorithm has no formal specification. However,
it has many implementations, most often referred to as _Electrum-Style Message
Signing_.

Key details about this implementation:

- the default _magic string_ is `"DarkCoin Signed Message:\n"`
- the hash format is `magicStrVarSize + magicStr + msgVarSize + msg`
- the hash algorithm is double-sha256
- the _recID_ is the first byte of the signature ("compressed"), either:
  - `27 + 4 + 0` (for 0x02)
  - OR `27 + 4 + 1` (for 0x03)
- the "magic" naming convention is used to differentiate from standard hashes,
  signatures, etc

## References

- implemented in [dashmsg](https://github.com/dashhive/dashmsg),
  [BC PR #524](https://github.com/bitcoin/bitcoin/pull/524/files)
- discussed in
  [What is Electrum-style Signature](https://ethereum.stackexchange.com/questions/55241/what-is-electrum-style-signature),
  [Satoshi-style Message Signing](https://delvingbitcoin.org/t/satoshi-style-message-signing/850/2),
  [How are Bitcoin Signed Messages generated?](https://bitcoin.stackexchange.com/questions/77324/how-are-bitcoin-signed-messages-generated),
  [Ethers: Signing Messages](https://docs.ethers.org/v6/cookbook/signing/#cookbook-signing-messages)
