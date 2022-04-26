const web3 = require("web3");
const assert = require("assert");
const Web3 = new web3();
const bip39 = require("bip39");
const HDKey = require("hdkey");

//// Generate Wallet Address
const generateWallet = async () => {
  const mneomonic = bip39.generateMnemonic(256);
  const seed = await bip39.mnemonicToSeed(mneomonic);
  const masterKeyBuff = HDKey.fromMasterSeed(seed);
  const BIP32EXTENDED = await masterKeyBuff.derive("m/44'/60'/0'/0/0");
  const credential = {
    AppWalletAddress: Web3.eth.accounts.privateKeyToAccount(
      BIP32EXTENDED.privateKey.toString("hex"),
      true
    ).address,
    AppPrivateKey: "0x" + BIP32EXTENDED.privateKey.toString("hex"),
    AppPublicKey: "0x" + BIP32EXTENDED.publicKey.toString("hex"),
    RecoveryPhrase: mneomonic,
  };
  return credential;
};

//// Generate Wallet Address
const restoreWallet = async (mneomonic) => {
  const seed = await bip39.mnemonicToSeed(mneomonic);
  const masterKeyBuff = HDKey.fromMasterSeed(seed);
  const BIP32EXTENDED = await masterKeyBuff.derive("m/44'/60'/0'/0/0");
  const credential = {
    AppWalletAddress: Web3.eth.accounts.privateKeyToAccount(
      BIP32EXTENDED.privateKey.toString("hex"),
      true
    ).address,
    AppPrivateKey: "0x" + BIP32EXTENDED.privateKey.toString("hex"),
    AppPublicKey: "0x" + BIP32EXTENDED.publicKey.toString("hex"),
    RecoveryPhrase: mneomonic,
  };
  return credential;
};

const testGenerateWallet = async () => {
  const credential = await generateWallet();
  console.log("GENERATED CREDS: ", credential);
  assert(
    Web3.utils.isAddress(credential.AppWalletAddress) === true,
    "Assertion Error: Wallet Address Generation error"
  );
  assert(
    Web3.utils.toChecksumAddress(credential.AppWalletAddress) ===
      credential.AppWalletAddress,
    "Assertion Error: Wallet Address checksum error"
  );

  assert(
    Web3.eth.accounts.privateKeyToAccount(credential.AppPrivateKey, true)
      .address === credential.AppWalletAddress,
    "Assertion Error: Wallet Address and Private key pair invalid"
  );

  //// Implementation of Signature
  const SignData = async (privateKey, walletAddress) => {
    const Json_data = {
      name: "Pratap Mridha",
      AppWalletAddress: walletAddress,
      timeStamp: Date.now(),
      validTill: new Date().getTime() + 24 * 60 * 60 * 1000,
    };

    const signedByWallet = await Web3.eth.accounts.sign(
      JSON.stringify(Json_data),
      privateKey
    );

    return {
      data: Json_data,
      signedByWallet,
    };
  };
  //// Implementation of Recover Wallet from Signature
  const getWalletAddresFromSign = async (
    data,
    dataHash,
    signature,
    signedByWallet
  ) => {
    assert(
      Web3.eth.accounts.recover(data, signature) ===
        Web3.eth.accounts.recover(signedByWallet),
      "Assettion Error : WalletAddress Generation Dispute"
    );
    assert(
      dataHash === Web3.eth.accounts.hashMessage(data),
      "Assettion Error : Data and DataHash dispute"
    );
    return {
      message: data,
      walletAddress: Web3.eth.accounts.recover(signedByWallet),
    };
  };

  const restoreCred = await restoreWallet(credential.RecoveryPhrase);
  assert(
    credential.AppPrivateKey === restoreCred.AppPrivateKey,
    "Assertion Error: Wallet Address Recovery Error"
  );
  assert(
    credential.AppPublicKey === restoreCred.AppPublicKey,
    "Assertion Error: Wallet Address Recovery Error"
  );
  assert(
    credential.AppWalletAddress === restoreCred.AppWalletAddress,
    "Assertion Error: Wallet Address Recovery Error"
  );
  assert(
    credential.RecoveryPhrase === restoreCred.RecoveryPhrase,
    "Assertion Error: Wallet Address Recovery Error"
  );

  console.log("RECOVERD CREDS", restoreCred);

  const { data, signedByWallet } = await SignData(
    credential.AppPrivateKey,
    credential.AppWalletAddress
  );
  console.log(signedByWallet);
  const { message, walletAddress } = await getWalletAddresFromSign(
    JSON.stringify(data),
    signedByWallet.messageHash,
    signedByWallet.signature,
    signedByWallet
  );

  assert(
    credential.AppWalletAddress === walletAddress,
    "Assertion Error : Wallet address after signture decrypt Mismatched"
  );
  console.log(JSON.parse(message), { Wallet: walletAddress });
};

testGenerateWallet();
