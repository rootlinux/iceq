import factory from "./curveasm";

interface KeyPair {
  pubKey: ArrayBuffer;
  privKey: ArrayBuffer;
}

interface CurveModule {
  HEAPU8: Uint8Array;
  _malloc(size: number): number;
  _free(ptr: number): void;
  _curve25519_donna(mypublic_ptr: number, secret_ptr: number, basepoint_ptr: number): number;
  _curve25519_sign(
    signature_ptr: number,
    privateKey_ptr: number,
    message_ptr: number,
    message_len: number,
  ): number;
  _curve25519_verify(
    signature_ptr: number,
    privateKey_ptr: number,
    message_ptr: number,
    message_len: number,
  ): number;
}

const instancePromise = factory();

class Curve25519Wrapper {
  static async create(): Promise<Curve25519Wrapper> {
    const instance = await instancePromise;
    return new Curve25519Wrapper(instance as CurveModule);
  }

  private readonly module: CurveModule;
  private readonly basepoint: Uint8Array;

  constructor(module: CurveModule) {
    this.module = module;
    this.basepoint = new Uint8Array(32).fill(0);
    this.basepoint[0] = 9;
  }

  private allocate(bytes: Uint8Array): number {
    const address = this.module._malloc(bytes.length);
    this.module.HEAPU8.set(bytes, address);
    return address;
  }

  private readBytes(address: number, length: number, out: Uint8Array): void {
    out.set(this.module.HEAPU8.subarray(address, address + length));
  }

  keyPair(privKey: ArrayBuffer): KeyPair {
    const priv = new Uint8Array(privKey);
    priv[0] = (priv[0] ?? 0) & 248;
    priv[31] = (priv[31] ?? 0) & 127;
    priv[31] = (priv[31] ?? 0) | 64;

    const publicKeyPtr = this.module._malloc(32);
    const privateKeyPtr = this.allocate(priv);
    const basepointPtr = this.allocate(this.basepoint);

    const err = this.module._curve25519_donna(publicKeyPtr, privateKeyPtr, basepointPtr);
    if (err !== 0) {
      throw new Error(`Error performing curve scalar multiplication: ${err}`);
    }

    const res = new Uint8Array(32);
    this.readBytes(publicKeyPtr, 32, res);

    this.module._free(publicKeyPtr);
    this.module._free(privateKeyPtr);
    this.module._free(basepointPtr);

    return { pubKey: res.buffer, privKey: priv.buffer };
  }

  sharedSecret(pubKey: ArrayBuffer, privKey: ArrayBuffer): ArrayBuffer {
    const sharedKeyPtr = this.module._malloc(32);
    const privateKeyPtr = this.allocate(new Uint8Array(privKey));
    const basepointPtr = this.allocate(new Uint8Array(pubKey));

    const err = this.module._curve25519_donna(sharedKeyPtr, privateKeyPtr, basepointPtr);
    if (err !== 0) {
      throw new Error(`Error performing curve scalar multiplication: ${err}`);
    }

    const res = new Uint8Array(32);
    this.readBytes(sharedKeyPtr, 32, res);

    this.module._free(sharedKeyPtr);
    this.module._free(privateKeyPtr);
    this.module._free(basepointPtr);

    return res.buffer;
  }

  sign(privKey: ArrayBuffer, message: ArrayBuffer): ArrayBuffer {
    const signaturePtr = this.module._malloc(64);
    const privateKeyPtr = this.allocate(new Uint8Array(privKey));
    const messagePtr = this.allocate(new Uint8Array(message));

    this.module._curve25519_sign(signaturePtr, privateKeyPtr, messagePtr, message.byteLength);

    const res = new Uint8Array(64);
    this.readBytes(signaturePtr, 64, res);

    this.module._free(signaturePtr);
    this.module._free(privateKeyPtr);
    this.module._free(messagePtr);

    return res.buffer;
  }

  verify(pubKey: ArrayBuffer, message: ArrayBuffer, sig: ArrayBuffer): boolean {
    const publicKeyPtr = this.allocate(new Uint8Array(pubKey));
    const signaturePtr = this.allocate(new Uint8Array(sig));
    const messagePtr = this.allocate(new Uint8Array(message));

    const res = this.module._curve25519_verify(signaturePtr, publicKeyPtr, messagePtr, message.byteLength);

    this.module._free(publicKeyPtr);
    this.module._free(signaturePtr);
    this.module._free(messagePtr);

    return res !== 0;
  }
}

export class AsyncCurve25519Wrapper {
  curvePromise: Promise<Curve25519Wrapper>;

  constructor() {
    this.curvePromise = Curve25519Wrapper.create();
  }

  async keyPair(privKey: ArrayBuffer): Promise<KeyPair> {
    return (await this.curvePromise).keyPair(privKey);
  }

  async sharedSecret(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> {
    return (await this.curvePromise).sharedSecret(pubKey, privKey);
  }

  async sign(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer> {
    return (await this.curvePromise).sign(privKey, message);
  }

  async verify(pubKey: ArrayBuffer, message: ArrayBuffer, sig: ArrayBuffer): Promise<boolean> {
    return (await this.curvePromise).verify(pubKey, message, sig);
  }
}
