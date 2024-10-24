#!/usr/bin/env node

import DashKeys from "dashkeys";
import DashMessage from "dashmessage";
import Secp256k1 from "@dashincubator/secp256k1";

let boilerplate = {
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

async function main() {
  let messageText = "dte2022-akerdemelidis|estoever|mmason";
  let address = "XyBmeuLa8y3D3XmzPvCTj5PVh7WvMPkLn1";
  // changing any letter should cause failure
  let sig =
    "H2Opy9NX72iPZRcDVEHrFn2qmVwWMgc+DKILdVxl1yfmcL2qcpu9esw9wcD7RH0/dJHnIISe5j39EYahorWQM7I=";

  await mustVerify(address, messageText, sig);

  console.info(`verified`);
}

main();
