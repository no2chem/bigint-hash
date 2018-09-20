import {toBigIntBE} from 'bigint-buffer';
import * as crypto from 'crypto';

declare var process: {browser: boolean;};

declare type OpenSSLHandle = {};
interface OpenSSLInterface {
  getHashHandle(type: OpenSSLHashType): OpenSSLHandle;
  getHashDigestBigInt(handle: OpenSSLHandle): bigint;
  getHashDigestBuffer(handle: OpenSSLHandle): Buffer;
  hashBuffer(handle: OpenSSLHandle, buf: Buffer): void;
  hashBufferOneshotBigInt(type: OpenSSLHashType, buf: Buffer): bigint;
  hashBufferOneshotBuffer(type: OpenSSLHashType, buf: Buffer): Buffer;
}

declare type KeccakHandle = {};
interface KeccakInterface {
  getHashHandle(type: KeccakHashType): KeccakHandle;
  getHashDigestBigInt(handle: KeccakHandle, type: KeccakHashType): bigint;
  getHashDigestBuffer(handle: KeccakHandle, type: KeccakHashType): Buffer;
  hashBuffer(handle: KeccakHandle, buf: Buffer): void;
  hashBufferOneshotBigInt(type: KeccakHashType, buf: Buffer): bigint;
  hashBufferOneshotBuffer(type: KeccakHashType, buf: Buffer): Buffer;
}

enum OpenSSLHashType {
  OPENSSL_MD5 = 0,
  OPENSSL_MD4 = 1,
  OPENSSL_SHA1 = 2,
  OPENSSL_SHA224 = 3,
  OPENSSL_SHA256 = 4,
  OPENSSL_SHA384 = 5,
  OPENSSL_SHA512 = 6
}


enum KeccakHashType {
  KECCAK_224 = 0,
  KECCAK_256 = 1,
  KECCAK_384 = 2,
  KECCAK_512 = 3,

  SHA3_224 = 4,
  SHA3_256 = 5,
  SHA3_384 = 6,
  SHA3_512 = 7
}

let libopenssl: OpenSSLInterface;
let libkeccak: KeccakInterface;
let keccak: (hashName: string) => crypto.Hash;
let fallback = process.browser;

if (!process.browser) {
  try {
    libopenssl = require('bindings')('openssl');
    libkeccak = require('bindings')('keccak');
  } catch (e) {
    console.warn(e);
    console.warn(
        'bigint-crypto: Failed to load bindings, pure JS will be used (try npm run rebuild?)');
    fallback = true;
    keccak = require('keccak');
  }
} else {
  keccak = require('keccak');
}

export interface Hash {
  digest(output?: OutputType): Buffer|string|bigint;
  digestBigInt(): bigint;
  update(data: string|Buffer, inputEncoding?: InputEncoding): Hash;
}

/**
 * Represents a string that can be passed to request a supported hashing
 * algorithm.
 */
export enum HashType {
  /**
   * MD5, 128-bit digest as specified in RFC 1321. "Cryptographically broken
   * and unsuitable for further use."
   */
  MD5 = 'md5',
  /** SHA-1, a 160-bit digest. No longer considered secure. */
  SHA1 = 'sha1',
  /** SHA-224, a 224-bit digest from the SHA-2 family. */
  SHA224 = 'sha224',
  /** SHA-256, a 256-bit digest from the SHA-2 family. */
  SHA256 = 'sha256',
  /** SHA-384, a 384-bit digest from the SHA-2 family. */
  SHA384 = 'sha384',
  /** SHA-512, a 512-bit digest from the SHA-2 family. */
  SHA512 = 'sha512',
  /**
   * SHA3-224, a 224-bit digest using the Keccak family, with 0x6 used for
   * padding.
   */
  SHA3_224 = 'sha3-224',
  /**
   * SHA3-256, a 256-bit digest using the Keccak family, with 0x6 used for
   * padding.
   */
  SHA3_256 = 'sha3-256',
  /**
   * SHA3-384, a 384-bit digest using the Keccak family, with 0x6 used for
   * padding.
   */
  SHA3_384 = 'sha3-384',
  /**
   * SHA3-512, a 512-bit digest using the Keccak family, with 0x6 used for
   * padding.
   */
  SHA3_512 = 'sha3-512',
  /**
   * Keccak224, a 224-bit digest using the Keccak family, with 0x0 used for
   * padding.
   */
  KECCAK224 = 'keccak224',
  /**
   * Keccak256, a 256-bit digest using the Keccak family, with 0x0 used for
   * padding. Commonly used for Ethereum.
   */
  KECCAK256 = 'keccak256',
  /**
   * Keccak384, a 384-bit digest using the Keccak family, with 0x0 used for
   * padding.
   */
  KECCAK384 = 'keccak384',
  /**
   * Keccak512, a 512-bit digest using the Keccak family, with 0x0 used for
   * padding.
   */
  KECCAK512 = 'keccak512'
}

/** Reperesents the types of input encoding which may be used by a string. */
export enum InputEncoding {
  /** UTF-8, the default encoding */
  UTF8 = 'utf8',
  /** ASCII, without UTF-8 extensions. */
  ASCII = 'ascii',
  /** Latin 1, as specified in ISO-8859-1 */
  LATIN1 = 'latin1'
}

/** Reperesents the permitted set of output types for a digest. */
export enum OutputType {
  /** Output a bigint digest. */
  BigInt = 'bigint',
  /** Output a buffer digest. */
  Buffer = 'buffer'
}

/** An internal hasher which calls OpenSSL. Do not use directly. */
export class OpensslHasher implements Hash {
  private disposed = false;
  static getOpensslType(hash: HashType): OpenSSLHashType {
    switch (hash) {
      case HashType.MD5:
        return OpenSSLHashType.OPENSSL_MD5;
      case HashType.SHA1:
        return OpenSSLHashType.OPENSSL_SHA1;
      case HashType.SHA224:
        return OpenSSLHashType.OPENSSL_SHA224;
      case HashType.SHA256:
        return OpenSSLHashType.OPENSSL_SHA256;
      case HashType.SHA384:
        return OpenSSLHashType.OPENSSL_SHA384;
      case HashType.SHA512:
        return OpenSSLHashType.OPENSSL_SHA512;
      default:
        throw new Error(`Unsupported hash type ${hash}`);
    }
  }
  constructor(
      hash: HashType, private opensslType = OpensslHasher.getOpensslType(hash),
      private opensslHandle = fallback ?
          crypto.createHash(hash) :
          libopenssl.getHashHandle(opensslType)) {}

  digest(output: OutputType = OutputType.Buffer) {
    if (this.disposed) {
      throw new Error('Digest a disposed hasher');
    }
    this.disposed = true;
    switch (output) {
      case OutputType.BigInt:
        if (fallback) {
          return toBigIntBE((this.opensslHandle as crypto.Hash).digest());
        }
        return libopenssl.getHashDigestBigInt(this.opensslHandle);
      case OutputType.Buffer:
        if (fallback) {
          return (this.opensslHandle as crypto.Hash).digest();
        }
        return libopenssl.getHashDigestBuffer(this.opensslHandle);
      default:
        throw new Error('Unsupported output type');
    }
  }

  digestBigInt(): bigint {
    return this.digest(OutputType.BigInt) as bigint;
  }

  update(data: string|Buffer, inputEncoding?: InputEncoding): Hash {
    if (this.disposed) {
      throw new Error('Updating a disposed hasher');
    }
    if ((data as Buffer).byteLength === undefined) {
      // this is a string
      data = Buffer.from(data as string, inputEncoding);
    }
    if (fallback) {
      (this.opensslHandle as crypto.Hash).update(data);
      return this;
    }
    libopenssl.hashBuffer(this.opensslHandle, data as Buffer);
    return this;
  }
}

/**
 * An internal hasher which calls the eXtended Keccak Code Package. Do not use
 * directly.
 */
export class KeccakHasher implements Hash {
  private disposed = false;
  static getKeccakType(hash: HashType): KeccakHashType {
    switch (hash) {
      case HashType.SHA3_224:
        return KeccakHashType.SHA3_224;
      case HashType.SHA3_256:
        return KeccakHashType.SHA3_256;
      case HashType.SHA3_384:
        return KeccakHashType.SHA3_384;
      case HashType.SHA3_512:
        return KeccakHashType.SHA3_512;
      case HashType.KECCAK224:
        return KeccakHashType.KECCAK_224;
      case HashType.KECCAK256:
        return KeccakHashType.KECCAK_256;
      case HashType.KECCAK384:
        return KeccakHashType.KECCAK_384;
      case HashType.KECCAK512:
        return KeccakHashType.KECCAK_512;
      default:
        throw new Error(`Unsupported hash type ${hash}`);
    }
  }

  constructor(
      hash: HashType, private keccakType = KeccakHasher.getKeccakType(hash),
      private keccakHandle = fallback ? keccak(hash) :
                                        libkeccak.getHashHandle(keccakType)) {}

  digest(output: OutputType = OutputType.Buffer) {
    if (this.disposed) {
      throw new Error('Digest a disposed hasher');
    }
    this.disposed = true;
    if (fallback) {
      const result = (this.keccakHandle as crypto.Hash).digest();
      switch (output) {
        case OutputType.BigInt:
          return toBigIntBE(result);
        case OutputType.Buffer:
          return result;
        default:
          throw new Error('Unsupported output type');
      }
    }

    switch (output) {
      case OutputType.BigInt:
        return libkeccak.getHashDigestBigInt(
            this.keccakHandle, this.keccakType);
      case OutputType.Buffer:
        return libkeccak.getHashDigestBuffer(
            this.keccakHandle, this.keccakType);
      default:
        throw new Error('Unsupported output type');
    }
  }

  digestBigInt(): bigint {
    return this.digest(OutputType.BigInt) as bigint;
  }

  update(data: string|Buffer, inputEncoding?: InputEncoding): Hash {
    if (this.disposed) {
      throw new Error('Updating a disposed hasher');
    }
    if ((data as Buffer).byteLength === undefined) {
      // this is a string
      data = Buffer.from(data as string, inputEncoding);
    }
    if (fallback) {
      (this.keccakHandle as crypto.Hash).update(data);
    } else {
      libkeccak.hashBuffer(this.keccakHandle, data as Buffer);
    }
    return this;
  }
}

/**
 * Obtain a hasher instance for hashing. If you will only hash a single buffer,
 *  call the [[hashAsBigInt]] or [[hashAsBuffer]] functions instead, as they
 *  yield better performance.
 *
 *  @param hash The type of algorithm to support
 *
 *  @returns A [[Hash]] instance for hashing.
 */
export function getHasher(hash: HashType): Hash {
  switch (hash) {
    case HashType.MD5:
    case HashType.SHA1:
    case HashType.SHA224:
    case HashType.SHA256:
    case HashType.SHA384:
    case HashType.SHA512:
      return new OpensslHasher(hash);
    case HashType.SHA3_224:
    case HashType.SHA3_256:
    case HashType.SHA3_384:
    case HashType.SHA3_512:
    case HashType.KECCAK224:
    case HashType.KECCAK256:
    case HashType.KECCAK384:
    case HashType.KECCAK512:
      return new KeccakHasher(hash);
    default:
      throw new Error(`Unsupported hash type!`);
  }
}

/**
 * Hash the given buffer using the hashing algorithm specified, returning
 *  the digest as a bigint.
 *
 *  @param hash The hash algorithm to use.
 *  @param buf  The buffer to use.
 *
 *  @returns A bigint with the message digest.
 */
export function hashAsBigInt(hash: HashType, buf: Buffer): bigint {
  switch (hash) {
    case HashType.MD5:
    case HashType.SHA1:
    case HashType.SHA224:
    case HashType.SHA256:
    case HashType.SHA384:
    case HashType.SHA512:
      if (fallback) {
        return toBigIntBE(crypto.createHash(hash).update(buf).digest());
      }
      return libopenssl.hashBufferOneshotBigInt(
          OpensslHasher.getOpensslType(hash), buf);
    case HashType.SHA3_224:
    case HashType.SHA3_256:
    case HashType.SHA3_384:
    case HashType.SHA3_512:
    case HashType.KECCAK224:
    case HashType.KECCAK256:
    case HashType.KECCAK384:
    case HashType.KECCAK512:
      if (fallback) {
        return toBigIntBE(keccak(hash).update(buf).digest());
      }
      return libkeccak.hashBufferOneshotBigInt(
          KeccakHasher.getKeccakType(hash), buf);
    default:
      throw new Error(`Unsupported hash type!`);
  }
}

/**
 * Hash the given buffer using the hashing algorithm specified, returning
 *  the digest as a Buffer.
 *
 *  @param hash The hash algorithm to use.
 *  @param buf  The buffer to use.
 *
 *  @returns A buffer with the message digest.
 */
export function hashAsBuffer(hash: HashType, buf: Buffer): Buffer {
  switch (hash) {
    case HashType.MD5:
    case HashType.SHA1:
    case HashType.SHA224:
    case HashType.SHA256:
    case HashType.SHA384:
    case HashType.SHA512:
      if (fallback) {
        return crypto.createHash(hash).update(buf).digest();
      }
      return libopenssl.hashBufferOneshotBuffer(
          OpensslHasher.getOpensslType(hash), buf);
    case HashType.SHA3_224:
    case HashType.SHA3_256:
    case HashType.SHA3_384:
    case HashType.SHA3_512:
    case HashType.KECCAK224:
    case HashType.KECCAK256:
    case HashType.KECCAK384:
    case HashType.KECCAK512:
      if (fallback) {
        return keccak(hash).update(buf).digest();
      }
      return libkeccak.hashBufferOneshotBuffer(
          KeccakHasher.getKeccakType(hash), buf);
    default:
      throw new Error(`Unsupported hash type!`);
  }
}