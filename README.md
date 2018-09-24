# 💪🔢🔒 bigint-hash: Hashing for TC39 BigInt Proposal 
[![NPM Package](https://img.shields.io/npm/v/bigint-hash.svg?style=flat-square)](https://www.npmjs.org/package/bigint-hash)
[![Build Status](https://img.shields.io/travis/com/no2chem/bigint-hash.svg?branch=master&style=flat-square)](https://travis-ci.com/no2chem/bigint-hash)
[![Coverage Status](https://img.shields.io/coveralls/no2chem/bigint-hash.svg?style=flat-square)](https://coveralls.io/r/no2chem/bigint-hash)
![node](https://img.shields.io/node/v/bigint-hash.svg?style=flat-square)

[bigint-hash](https://www.npmjs.org/package/bigint-hash) provides common hashing routines (MD5, SHA, SHA-2, SHA-3, Keccak, xxHash) that use N-API routines to return [TC39 Proposed BigInts](https://github.com/tc39/proposal-bigint) as digests instead of Buffers, strings or
Uint8Arrays. BigInts are especially useful in the context of hashes because they can be compared 10-100x faster than
buffers (see [here](https://github.com/no2chem/bigint-buffer#why-use-bigints)). In addition, bigints are
managed much more efficiently than Buffers, which are allocated outside the V8 heap. bigint-hash also provides routines
which are optimized for the common case of hashing a single buffer. As a result, this library is about
5x faster than Node.js's built in [crypto API](https://nodejs.org/api/crypto.html), even though the same underlying 
OpenSSL library is used. In the browser, bigint-hash falls back to polyfills provided for crypto libraries. 
bigint-hash aims for:

- __Drop-in compatibility with Node.js's crypto API.__  While we don't support stream functionality yet, in most cases you
can replace references to Node.js's API with bigint-hash.

- __High performance.__ bigint-hash aims to be the fastest way to obtain a hash in Node.js, using N-API bindings to
optimized libraries whenever possible. This results in up to a 7x speedup over existing libraries, even when
not using bigint. With xxHash, we can hash at ~2.5M hashes/second. See benchmarks [here](https://github.com/no2chem/bigint-hash#performance).

- __Support for a wide variety of hash algorithms.__ bigint-hash currently supports MD5, the SHA-1, SHA-2 family of
hashing algorithms (with OpenSSL) and SHA-3 and Keccak (through the eXtended Keccak Code Package). We also now support
xxHash, an extremely fast non-cryptographic hash algorithm. More algorithms may be supported in the future.

# Usage

Install via [NPM]((https://www.npmjs.org/package/bigint-hash)):
```
> npm install --save bigint-hash
```

You can find API documentation [here](https://no2chem.github.io/bigint-hash).

To get a Hash instance, use the `getHasher` function with a supported hash algorithm. You can find supported
types in the documentation for the [HashType enum](https://no2chem.github.io/bigint-hash/enums/hashtype.html), or
you can pass most OpenSSL algorithm names (like `'sha256'`).
```
import {getHasher, OutputType, HashType} from 'bigint-hash';

// As with Node.js crypto API
getHasher(HashType.SHA1).update(Buffer.from('hello world')).digest();

// To get a bigInt, use either:
getHasher(HashType.SHA1).update(Buffer.from('hello world')).digest(OutputType.BigInt);
getHasher(HashType.SHA1).update(Buffer.from('hello world')).digestAsBigInt();
```

Only hashing a single buffer? Use the one-shot API for better performance:
```
import {hashAsBigInt, hashAsBuffer} from 'bigint-hash';

hashAsBigInt(HashType.SHA1, Buffer.from('hello world'));
hashAsBuffer(HashType.SHA1, Buffer.from('hello world'));
```

# Performance

So how does it all perform? Benchmarks can be run by using `npm run benchmark`.

For example, for SHA256:
```
Running SHA256...
node-crypto-buf: 274981±6.02% ops/s 3636.62±893.055 ns/op (64 runs)
node-crypto-bigint: 267242±5.91% ops/s 3741.93±930.464 ns/op (68 runs)
biginthash-buf: 403311±13.51% ops/s 2479.48±1439.719 ns/op (71 runs)
biginthash-bigint: 505348±34.12% ops/s 1978.83±2733.946 ns/op (63 runs)
biginthash-oneshot-bigint: 1010083±0.65% ops/s 990.02±31.829 ns/op (93 runs)
biginthash-oneshot-buffer: 591309±1.96% ops/s 1691.16±155.995 ns/op (85 runs)
Fastest is biginthash-oneshot-bigint
```

Here, `node-crypto-buf` is the standard Node.js API, and `node-crypto-bigint` is that same API
with the overhead of converting to a bigint (using [bigint-buffer](https://github.com/no2chem/bigint-buffer)).

Doing the conversion to bigint natively, `biginthash-bigint`, results in 1.8x better performance. Interestingly,
`biginthash-buf`, which calls OpenSSL and should perform the same as `node-crypto-buf`, performs 1.4x better, which
should be investigated. 

Using the one-shot API `biginthash-oneshot-bigint` yields about 3.4x better performance, thanks to not having to
allocate an external context to hold hashing state and schedule garbage collection.

For SHA3, we compare against the widely used [keecak](https://github.com/cryptocoinjs/keccak) library.
```
Running SHA3_256...
sha3-buf: 140667±13.36% ops/s 7108.97±4278.996 ns/op (78 runs)
sha3-bigint: 146018±1.24% ops/s 6848.49±395.861 ns/op (84 runs)
biginthash-buf: 365119±8.46% ops/s 2738.83±1010.152 ns/op (73 runs)
biginthash-bigint: 450430±29.27% ops/s 2220.10±2652.172 ns/op (64 runs)
biginthash-oneshot-bigint: 1010901±0.34% ops/s 989.22±16.845 ns/op (94 runs)
biginthash-oneshot-buffer: 584744±1.52% ops/s 1710.15±123.457 ns/op (87 runs)
Fastest is biginthash-oneshot-bigint
```

`biginthash-oneshot-bigint` performs 7x faster than the `sha3-buf`, which just uses the `keccak` library. 
Even `biginthash-buf` performs 2.6x better than `sha3-buf`. This is because bigint-hash uses an optimized version
from the eXtended Keccak Code Package, while keccak uses the reference implementation.

There's also a significant amount of noise in the non-oneshot APIs. This is probably due to garbage collection overheads,
as the Hasher must allocate temporary state, the noise is probably due to garbage collection kicking in much more frequently. 
With the oneshot API there is significantly less noise, as less garbage is generated in the first place.

Version 0.2.0 introduced support for xxHash. This provides very fast (but non-cryptographic hashes):

```
Running xxHash64...
xxhash-node: 470517±8.23% ops/s 2125.32±697.178 ns/op (61 runs)
xxhashjs-digest: 148855±1.42% ops/s 6717.97±460.271 ns/op (90 runs)
xxhashjs-oneshot: 142618±2.80% ops/s 7011.76±927.270 ns/op (86 runs)
biginthash-buf: 423390±17.42% ops/s 2361.89±1625.679 ns/op (60 runs)
biginthash-bigint: 738984±21.47% ops/s 1353.21±1204.176 ns/op (66 runs)
biginthash-oneshot-bigint: 2435419±1.67% ops/s 410.61±32.956 ns/op (89 runs)
biginthash-oneshot-buffer: 762413±11.00% ops/s 1311.62±658.480 ns/op (80 runs)
Fastest is biginthash-oneshot-bigint
```

Interestingly, the bigint version is 3x more performant than the buffer version, highlighting
how much more buffer allocation costs over bigints.