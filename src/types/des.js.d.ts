declare module "des.js" {
  interface CipherOptions {
    type: "encrypt" | "decrypt";
    key: Uint8Array;
    iv: Uint8Array;
    padding?: boolean;
  }

  interface Cipher {
    update(data: Uint8Array): number[];
    final(data?: Uint8Array): number[];
  }

  interface CipherConstructor {
    new(options: CipherOptions): Cipher;
  }

  const des: {
    DES: CipherConstructor;
    CBC: {
      instantiate(base: CipherConstructor): {
        create(options: CipherOptions): Cipher;
      };
    };
  };

  export default des;
}
