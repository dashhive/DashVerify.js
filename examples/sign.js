#!/usr/bin/env node

import DashKeys from "dashkeys";
import DashMessage from "dashmessage";
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
};

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

async function main() {
  let messageText = "dte2022-akerdemelidis|estoever|mmason";
  let wif = "XK5DHnAiSj6HQNsNcDkawd9qdp8UFMdYftdVZFuRreTMJtbJhk8i";

  let sig = await sign(wif, messageText);
  console.info(`Signature (base64):\n${sig}`);
  // H2Opy9NX72iPZRcDVEHrFn2qmVwWMgc+DKILdVxl1yfmcL2qcpu9esw9wcD7RH0/dJHnIISe5j39EYahorWQM7I=
}

main();
