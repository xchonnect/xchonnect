// ohttp-js ships types but its package `exports` map does not point to them; declare the
// subset the interop test uses.
declare module "ohttp-js" {
  interface KemContext {
    deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey>;
  }
  export class PublicKeyConfig {
    keyId: number;
    publicKey: CryptoKey;
    suite: { kemContext(): Promise<KemContext> };
    constructor(keyId: number, kem: number, kdf: number, aead: number, publicKey: CryptoKey | undefined);
  }
  interface ClientRequestContext {
    request: { encode(): Uint8Array<ArrayBuffer> };
    decodeAndDecapsulate(msg: Uint8Array): Promise<Uint8Array>;
    decapsulateResponse(response: Response): Promise<Response>;
  }
  export class Client {
    constructor(config: PublicKeyConfig);
    encapsulateRequest(request: Request): Promise<ClientRequestContext>;
  }
}
