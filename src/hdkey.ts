import * as bs58check from "bs58check";
import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";
import * as secp256k1 from "secp256k1";

const crypto = require("crypto");

var MASTER_SECRET = Buffer.from("Bitcoin seed", "utf8");
var HARDENED_OFFSET = 0x80000000;
var LEN = 78;

var BITCOIN_VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };

class HDKey {
  versions = BITCOIN_VERSIONS;
  depth = 0;
  index = 0;

  chainCode?: Buffer;
  parentFingerprint = 0;

  private _privateKey?: Buffer;
  private _publicKey?: Buffer;
  private _fingerprint = 0;
  private _identifier = Buffer.alloc(20, 0);

  constructor(versions?: typeof BITCOIN_VERSIONS) {
    if (versions) this.versions = versions;
  }

  get fingerprint() {
    return this._fingerprint;
  }

  get identifier() {
    return this._identifier;
  }

  get pubKeyHash() {
    return this.identifier;
  }

  get privateKey() {
    return this._privateKey;
  }

  get publicKey() {
    return this._publicKey;
  }

  set privateKey(value) {
    if (!value) return;

    equal(value.length, 32, "Private key must be 32 bytes.");
    assert(secp256k1.privateKeyVerify(value) === true, "Invalid private key");

    this._privateKey = value;
    this._publicKey = Buffer.from(secp256k1.publicKeyCreate(value, true));
    this._identifier = Buffer.from(hash160(this._publicKey));
    this._fingerprint = this._identifier.subarray(0, 4).readUInt32BE(0);
  }

  setPublicKey(value: Buffer) {
    assert(
      value.length === 33 || value.length === 65,
      "Public key must be 33 or 65 bytes."
    );
    assert(secp256k1.publicKeyVerify(value) === true, "Invalid public key");
    const publicKey =
      value.length === 65
        ? Buffer.from(secp256k1.publicKeyConvert(value, true))
        : value;

    this._publicKey = Buffer.from(publicKey);
    this._identifier = Buffer.from(hash160(publicKey));
    this._fingerprint = this._identifier.subarray(0, 4).readUInt32BE(0);
    this._privateKey = undefined;
  }

  get privateExtendedKey() {
    if (this._privateKey)
      return bs58check.encode(
        serialize(
          this,
          this.versions.private,
          Buffer.concat([Buffer.alloc(1, 0), this._privateKey])
        )
      );
    else return null;
  }

  get publicExtendedKey() {
    if (!this._publicKey) return null;
    return bs58check.encode(
      serialize(this, this.versions.public, this._publicKey)
    );
  }

  derive(path: string) {
    if (path === "m" || path === "M" || path === "m'" || path === "M'") {
      return this;
    }

    var entries = path.split("/");
    var hdkey: HDKey = this;
    entries.forEach(function (c, i) {
      if (i === 0) {
        assert(/^[mM]{1}/.test(c), 'Path must start with "m" or "M"');
        return;
      }

      var hardened = c.length > 1 && c[c.length - 1] === "'";
      var childIndex = parseInt(c, 10); // & (HARDENED_OFFSET - 1)
      assert(childIndex < HARDENED_OFFSET, "Invalid index");
      if (hardened) childIndex += HARDENED_OFFSET;

      hdkey = hdkey.deriveChild(childIndex);
    });

    return hdkey;
  }

  deriveChild(index: number): HDKey {
    const isHardened = index >= HARDENED_OFFSET;
    const indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(index, 0);

    let data;

    if (isHardened) {
      assert(this.privateKey, "Could not derive hardened child key");

      var pk = this.privateKey;
      var zb = Buffer.alloc(1, 0);
      pk = Buffer.concat([zb, pk!]);

      data = Buffer.concat([pk, indexBuffer]);
    } else {
      data = Buffer.concat([this._publicKey!, indexBuffer]);
    }

    const I = crypto.createHmac("sha512", this.chainCode).update(data).digest();
    const IL = I.slice(0, 32);
    var IR = I.slice(32);

    var hd = new HDKey(this.versions);

    if (this.privateKey) {
      try {
        hd.privateKey = Buffer.from(
          secp256k1.privateKeyTweakAdd(Buffer.from(this.privateKey), IL)
        );
      } catch (err) {
        return this.deriveChild(index + 1);
      }
    } else {
      try {
        hd.setPublicKey(
          Buffer.from(secp256k1.publicKeyTweakAdd(this._publicKey!, IL, true))
        );
      } catch (err) {
        return this.deriveChild(index + 1);
      }
    }

    hd.chainCode = IR;
    hd.depth = this.depth + 1;
    hd.parentFingerprint = this.fingerprint; // .readUInt32BE(0)
    hd.index = index;

    return hd;
  }

  sign(hash: Buffer) {
    return Buffer.from(
      secp256k1.ecdsaSign(
        Uint8Array.from(hash),
        Uint8Array.from(this._privateKey!)
      ).signature
    );
  }

  verify(hash: Buffer, signature: Buffer) {
    return secp256k1.ecdsaVerify(
      Uint8Array.from(signature),
      Uint8Array.from(hash),
      Uint8Array.from(this._publicKey!)
    );
  }

  wipePrivateData() {
    if (this._privateKey)
      crypto.randomBytes(this._privateKey.length).copy(this._privateKey);
    this._privateKey = undefined;
    return this;
  }

  toJSON() {
    return {
      xpriv: this.privateExtendedKey,
      xpub: this.publicExtendedKey,
    };
  }

  static fromMasterSeed(
    seedBuffer: Buffer,
    versions?: typeof BITCOIN_VERSIONS
  ) {
    var I = crypto
      .createHmac("sha512", MASTER_SECRET)
      .update(seedBuffer)
      .digest();
    var IL = I.slice(0, 32);
    var IR = I.slice(32);

    var hdkey = new HDKey(versions);
    hdkey.chainCode = IR;
    hdkey.privateKey = IL;

    return hdkey;
  }

  static fromExtendedKey(
    base58key: string,
    versions?: typeof BITCOIN_VERSIONS
  ) {
    versions = versions || BITCOIN_VERSIONS;
    var hdkey = new HDKey(versions);

    var keyBuffer = bs58check.decode(base58key);

    var version = keyBuffer.readUInt32BE(0);
    assert(
      version === versions.private || version === versions.public,
      "Version mismatch: does not match private or public"
    );

    hdkey.depth = keyBuffer.readUInt8(4);
    hdkey.parentFingerprint = keyBuffer.readUInt32BE(5);
    hdkey.index = keyBuffer.readUInt32BE(9);
    hdkey.chainCode = keyBuffer.slice(13, 45);

    var key = keyBuffer.slice(45);
    if (key.readUInt8(0) === 0) {
      // private
      assert(
        version === versions.private,
        "Version mismatch: version does not match private"
      );
      hdkey.privateKey = key.slice(1); // cut off first 0x0 byte
    } else {
      assert(
        version === versions.public,
        "Version mismatch: version does not match public"
      );
      hdkey.setPublicKey(key);
    }

    return hdkey;
  }

  static fromJSON(obj: ReturnType<HDKey["toJSON"]>) {
    return HDKey.fromExtendedKey(obj.xpriv!);
  }
}

function serialize(hdkey: HDKey, version: number, key: Buffer) {
  var buffer = Buffer.allocUnsafe(LEN);

  buffer.writeUInt32BE(version, 0);
  buffer.writeUInt8(hdkey.depth, 4);

  var fingerprint = hdkey.depth ? hdkey.parentFingerprint : 0x00000000;
  buffer.writeUInt32BE(fingerprint, 5);
  buffer.writeUInt32BE(hdkey.index, 9);

  hdkey.chainCode?.copy(buffer, 13);
  key.copy(buffer, 45);

  return buffer;
}

function hash160(buf: Buffer) {
  return ripemd160(sha256(buf));
}

const assert = (condition: any, error: string) => {
  if (!condition) throw new Error(error);
};

const equal = (a: any, b: any, error: string) => {
  if (a !== b) throw new Error(error);
};

export default HDKey;
