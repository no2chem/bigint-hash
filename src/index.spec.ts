import 'mocha';
declare var process: {browser: boolean;};

import * as chai from 'chai';
import * as path from 'path';

const lib = process.browser ? require('../../dist/browser') :
                              require(path.join(__dirname, '../dist/node'));


const getHasher = lib.getHasher;
const hashAsBigInt = lib.hashAsBigInt;
const HashType = lib.HashType;

// Needed for should.not.be.undefined.
/* tslint:disable:no-unused-expression */

chai.should();
const should = chai.should();

const assertEquals = (n0: BigInt, n1: BigInt) => {
  n0.toString(16).should.equal(n1.toString(16));
};

describe('Try empty hashes - BigInt', () => {
  it('should have a valid empty MD5', () => {
    assertEquals(
        getHasher(HashType.MD5).digestBigInt(),
        BigInt('0xd41d8cd98f00b204e9800998ecf8427e'));
  });

  it('should have a valid empty SHA1', () => {
    assertEquals(
        getHasher(HashType.SHA1).digestBigInt(),
        BigInt('0xda39a3ee5e6b4b0d3255bfef95601890afd80709'));
  });

  it('should have a valid empty SHA224', () => {
    assertEquals(
        getHasher(HashType.SHA224).digestBigInt(),
        BigInt('0xd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f'));
  });

  it('should have a valid empty SHA256', () => {
    assertEquals(
        getHasher(HashType.SHA256).digestBigInt(),
        BigInt(
            '0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'));
  });

  it('should have a valid empty SHA384', () => {
    assertEquals(
        getHasher(HashType.SHA384).digestBigInt(),
        BigInt(
            '0x38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b'));
  });

  it('should have a valid empty SHA512', () => {
    assertEquals(
        getHasher(HashType.SHA512).digestBigInt(),
        BigInt(
            '0xcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'));
  });

  it('should have a valid empty SHA3-224', () => {
    assertEquals(
        getHasher(HashType.SHA3_224).digestBigInt(),
        BigInt('0x6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7'));
  });

  it('should have a valid empty SHA3-256', () => {
    assertEquals(
        getHasher(HashType.SHA3_256).digestBigInt(),
        BigInt(
            '0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'));
  });

  it('should have a valid empty SHA3-384', () => {
    assertEquals(
        getHasher(HashType.SHA3_384).digestBigInt(),
        BigInt(
            '0x0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004'));
  });

  it('should have a valid empty SHA3-512', () => {
    assertEquals(
        getHasher(HashType.SHA3_512).digestBigInt(),
        BigInt(
            '0xa69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26'));
  });

  it('should have a valid empty xxHash32', () => {
    assertEquals(
        getHasher(HashType.xxHash32).digestBigInt(), BigInt('0x2cc5d05'));
  });

  it('should have a valid empty xxHash64', () => {
    assertEquals(
        getHasher(HashType.xxHash64).digestBigInt(),
        BigInt('0xef46db3751d8e999'));
  });
});


describe('Try empty hashes - OneShot BigInt', () => {
  it('should have a valid empty MD5', () => {
    assertEquals(
        hashAsBigInt(HashType.MD5, Buffer.from([])),
        BigInt('0xd41d8cd98f00b204e9800998ecf8427e'));
  });

  it('should have a valid empty SHA1', () => {
    assertEquals(
        hashAsBigInt(HashType.SHA1, Buffer.from([])),
        BigInt('0xda39a3ee5e6b4b0d3255bfef95601890afd80709'));
  });

  it('should have a valid empty SHA224', () => {
    assertEquals(
        hashAsBigInt(HashType.SHA224, Buffer.from([])),
        BigInt('0xd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f'));
  });

  it('should have a valid empty SHA256', () => {
    assertEquals(
        hashAsBigInt(HashType.SHA256, Buffer.from([])),
        BigInt(
            '0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'));
  });

  it('should have a valid empty SHA384', () => {
    assertEquals(
        hashAsBigInt(HashType.SHA384, Buffer.from([])),
        BigInt(
            '0x38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b'));
  });

  it('should have a valid empty SHA512', () => {
    assertEquals(
        hashAsBigInt(HashType.SHA512, Buffer.from([])),
        BigInt(
            '0xcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'));
  });

  it('should have a valid empty SHA3-224', () => {
    assertEquals(
        hashAsBigInt(HashType.SHA3_224, Buffer.from([])),
        BigInt('0x6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7'));
  });

  it('should have a valid empty SHA3-256', () => {
    assertEquals(
        hashAsBigInt(HashType.SHA3_256, Buffer.from([])),
        BigInt(
            '0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'));
  });

  it('should have a valid empty SHA3-384', () => {
    assertEquals(
        hashAsBigInt(HashType.SHA3_384, Buffer.from([])),
        BigInt(
            '0x0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004'));
  });

  it('should have a valid empty SHA3-512', () => {
    assertEquals(
        hashAsBigInt(HashType.SHA3_512, Buffer.from([])),
        BigInt(
            '0xa69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26'));
  });

  it('should have a valid empty xxHash32', () => {
    assertEquals(
        hashAsBigInt(HashType.xxHash32, Buffer.from([])), BigInt('0x2cc5d05'));
  });

  it('should have a valid empty xxHash64', () => {
    assertEquals(
        hashAsBigInt(HashType.xxHash64, Buffer.from([])),
        BigInt('0xef46db3751d8e999'));
  });
});



describe('Try empty hashes - Buffer', () => {
  it('should have a valid empty MD5', () => {
    getHasher(HashType.MD5)
        .digest()
        .should.deep.equal(
            Buffer.from('d41d8cd98f00b204e9800998ecf8427e', 'hex'));
  });

  it('should have a valid empty SHA1', () => {
    getHasher(HashType.SHA1)
        .digest()
        .should.deep.equal(
            Buffer.from('da39a3ee5e6b4b0d3255bfef95601890afd80709', 'hex'));
  });

  it('should have a valid empty SHA224', () => {
    getHasher(HashType.SHA224)
        .digest()
        .should.deep.equal(Buffer.from(
            'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f', 'hex'));
  });

  it('should have a valid empty SHA256', () => {
    getHasher(HashType.SHA256)
        .digest()
        .should.deep.equal(Buffer.from(
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'hex'));
  });

  it('should have a valid empty SHA384', () => {
    getHasher(HashType.SHA384)
        .digest()
        .should.deep.equal(Buffer.from(
            '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
            'hex'));
  });

  it('should have a valid empty SHA512', () => {
    getHasher(HashType.SHA512)
        .digest()
        .should.deep.equal(Buffer.from(
            'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
            'hex'));
  });

  it('should have a valid empty SHA3-224', () => {
    getHasher(HashType.SHA3_224)
        .digest()
        .should.deep.equal(Buffer.from(
            '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7', 'hex'));
  });

  it('should have a valid empty SHA3-256', () => {
    getHasher(HashType.SHA3_256)
        .digest()
        .should.deep.equal(Buffer.from(
            'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
            'hex'));
  });

  it('should have a valid empty SHA3-384', () => {
    getHasher(HashType.SHA3_384)
        .digest()
        .should.deep.equal(Buffer.from(
            '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004',
            'hex'));
  });

  it('should have a valid empty SHA3-512', () => {
    getHasher(HashType.SHA3_512)
        .digest()
        .should.deep.equal(Buffer.from(
            'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
            'hex'));
  });

  it('should have a valid empty xxHash32', () => {
    getHasher(HashType.xxHash32)
        .digest()
        .should.deep.equal(Buffer.from('02cc5d05', 'hex'));
  });

  it('should have a valid empty xxHash64', () => {
    getHasher(HashType.xxHash64)
        .digest()
        .should.deep.equal(Buffer.from('ef46db3751d8e999', 'hex'));
  });
});


describe('Try helloworld hash - BigInt', () => {
  it('should have a valid MD5', () => {
    assertEquals(
        getHasher(HashType.MD5)
            .update(Buffer.from('helloworld'))
            .digestBigInt(),
        BigInt('0xfc5e038d38a57032085441e7fe7010b0'));
  });

  it('should have a valid SHA1', () => {
    assertEquals(
        getHasher(HashType.SHA1)
            .update(Buffer.from('helloworld'))
            .digestBigInt(),
        BigInt('0x6adfb183a4a2c94a2f92dab5ade762a47889a5a1'));
  });

  it('should have a valid SHA224', () => {
    assertEquals(
        getHasher(HashType.SHA224)
            .update(Buffer.from('helloworld'))
            .digestBigInt(),
        BigInt('0xb033d770602994efa135c5248af300d81567ad5b59cec4bccbf15bcc'));
  });

  it('should have a valid SHA256', () => {
    assertEquals(
        getHasher(HashType.SHA256)
            .update(Buffer.from('helloworld'))
            .digestBigInt(),
        BigInt(
            '0x936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af'));
  });

  it('should have a valid SHA384', () => {
    assertEquals(
        getHasher(HashType.SHA384)
            .update(Buffer.from('helloworld'))
            .digestBigInt(),
        BigInt(
            '0x97982a5b1414b9078103a1c008c4e3526c27b41cdbcf80790560a40f2a9bf2ed4427ab1428789915ed4b3dc07c454bd9'));
  });

  it('should have a valid SHA512', () => {
    assertEquals(
        getHasher(HashType.SHA512)
            .update(Buffer.from('helloworld'))
            .digestBigInt(),
        BigInt(
            '0x1594244d52f2d8c12b142bb61f47bc2eaf503d6d9ca8480cae9fcf112f66e4967dc5e8fa98285e36db8af1b8ffa8b84cb15e0fbcf836c3deb803c13f37659a60'));
  });

  it('should have a valid SHA3-224', () => {
    assertEquals(
        getHasher(HashType.SHA3_224)
            .update(Buffer.from('helloworld'))
            .digestBigInt(),
        BigInt('0xc4797897c58a0640df9c4e9a8f30570364d9ed8450c78ed155278ac0'));
  });

  it('should have a valid SHA3-256', () => {
    assertEquals(
        getHasher(HashType.SHA3_256)
            .update(Buffer.from('helloworld'))
            .digestBigInt(),
        BigInt(
            '0x92dad9443e4dd6d70a7f11872101ebff87e21798e4fbb26fa4bf590eb440e71b'));
  });

  it('should have a valid SHA3-384', () => {
    assertEquals(
        getHasher(HashType.SHA3_384)
            .update(Buffer.from('helloworld'))
            .digestBigInt(),
        BigInt(
            '0xdc6104dc2caff3ce2ccecbc927463fc3241c8531901449f1b1f4787394c9b3aa55a9e201d0bb0b1b7d7f8892bc127216'));
  });

  it('should have a valid SHA3-512', () => {
    assertEquals(
        getHasher(HashType.SHA3_512)
            .update(Buffer.from('helloworld'))
            .digestBigInt(),
        BigInt(
            '0x938315ec7b0e0bcac648ae6f732f67e00f9c6caa3991627953434a0769b0bbb15474a429177013ed8a7e48990887d1e19533687ed2183fd2b6054c2e8828ca1c'));
  });

  it('should have a valid xxHash32', () => {
    assertEquals(
        getHasher(HashType.xxHash32)
            .update(Buffer.from('helloworld'))
            .digestBigInt(),
        BigInt('0x2362e202'));
  });

  it('should have a valid xxHash64', () => {
    assertEquals(
        getHasher(HashType.xxHash64)
            .update(Buffer.from('helloworld'))
            .digestBigInt(),
        BigInt('0x80111601aa1c6a4f'));
  });
});