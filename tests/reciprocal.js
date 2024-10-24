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
  recoverPubkey: async function (msgHash, signature, recovery, isCompressed) {
    let pubkeyBytes = await Secp256k1.recoverPublicKey(
      msgHash,
      signature,
      recovery,
      isCompressed,
    );
    return pubkeyBytes;
  },
  pubkeyToPkh: async function (pubkeyBytes) {
    let pkhBytes = await DashKeys.pubkeyToPkh(pubkeyBytes);
    return pkhBytes;
  },
};

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

async function test1() {
  let goodSig =
    "H2Opy9NX72iPZRcDVEHrFn2qmVwWMgc+DKILdVxl1yfmcL2qcpu9esw9wcD7RH0/dJHnIISe5j39EYahorWQM7I=";
  let badSig =
    "H2opy9NX72iPZRcDVEHrFn2qmVwWMgc+DKILdVxl1yfmcL2qcpu9esw9wcD7RH0/dJHnIISe5j39EYahorWQM7I=";

  let messageText = "dte2022-akerdemelidis|estoever|mmason";
  let wif = "XK5DHnAiSj6HQNsNcDkawd9qdp8UFMdYftdVZFuRreTMJtbJhk8i";
  let address = "XyBmeuLa8y3D3XmzPvCTj5PVh7WvMPkLn1";

  let sig = await sign(wif, messageText);
  if (sig !== goodSig) {
    throw new Error("unknown sig");
  }
  await mustVerify(address, messageText, sig);

  try {
    await mustVerify(address, messageText, badSig);
    throw new Error("failed to fail");
  } catch (e) {
    if (e.message === "failed to fail") {
      throw e;
    }
  }
}

async function test2() {
  let messageText = "Hello, World!";
  let wif = "XK5DHnAiSj6HQNsNcDkawd9qdp8UFMdYftdVZFuRreTMJtbJhk8i";
  let address = "XyBmeuLa8y3D3XmzPvCTj5PVh7WvMPkLn1";

  let sig = await sign(wif, messageText);
  await mustVerify(address, messageText, sig);
}

async function test3() {
  let wif = "XK5DHnAiSj6HQNsNcDkawd9qdp8UFMdYftdVZFuRreTMJtbJhk8i";
  let address = "XyBmeuLa8y3D3XmzPvCTj5PVh7WvMPkLn1";

  for (let i = 0; i < 100; i += 1) {
    let rndF = Math.random();
    rndF *= 550;
    rndF += 5;
    let len = Math.floor(rndF);

    let messageText = getRandomString(len);
    let sig = await sign(wif, messageText);
    await mustVerify(address, messageText, sig);
  }
}

function getRandomString(length) {
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz 0123456789~!@#$%^&*()|`\\/.;,<>";
  let result = "";
  const charactersLength = characters.length;

  for (let i = 0; i < length; i += 1) {
    let rndF = Math.random();
    rndF = rndF * charactersLength;
    let rnd = Math.floor(rndF);
    result += characters[rnd];
  }

  return result;
}

async function main() {
  await test1();
  await test2();
  await test3();

  console.info(`PASS`);
}

main();
