import * as benchmark from 'benchmark';
import {toBigIntBE} from 'bigint-buffer';
import * as crypto from 'crypto';

import {getHasher, hashAsBigInt, hashAsBuffer, HashType} from './index';

const keccak = require('keccak');
interface BenchmarkRun {
  name: string;
  hz: number;
  stats: benchmark.Stats;
}

// This file contains the benchmark test suite. It includes the benchmark and
// some lightweight boilerplate code for running benchmark.js. To
// run the benchmarks, execute `npm run benchmark` from the package directory.
const runSuite = (suite: benchmark.Suite, name: string) => {
  console.log(`\nRunning ${name}...`);
  // Reporter for each benchmark
  suite.on('cycle', (event: benchmark.Event) => {
    const benchmarkRun: BenchmarkRun = event.target as BenchmarkRun;
    const stats = benchmarkRun.stats as benchmark.Stats;
    const meanInNanos = (stats.mean * 1000000000).toFixed(2);
    const stdDevInNanos = (stats.deviation * 1000000000).toFixed(3);
    const runs = stats.sample.length;
    const ops = benchmarkRun.hz.toFixed(benchmarkRun.hz < 100 ? 2 : 0);
    const err = stats.rme.toFixed(2);

    console.log(`${benchmarkRun.name}: ${ops}±${err}% ops/s ${meanInNanos}±${
        stdDevInNanos} ns/op (${runs} run${runs === 0 ? '' : 's'})`);
  });

  suite.on('complete', () => {
    console.log(
        'Fastest is ' +
        suite.filter('fastest').map('name' as unknown as Function));
  });
  // Runs the test suite
  suite.run();
};

let suite = new benchmark.Suite();
// Tests the performance of a no-op.
suite.add('no-op', () => {});
runSuite(suite, 'basic');

// Test the performance of md5 under various schemes
suite = new benchmark.Suite('md5');
suite.add('node-crypto-buf', () => {
  crypto.createHash('md5').update(Buffer.from('hello world')).digest();
});
suite.add('node-crypto-bigint', () => {
  toBigIntBE(
      crypto.createHash('md5').update(Buffer.from('hello world')).digest());
});
suite.add('biginthash-buf', () => {
  getHasher(HashType.MD5).update(Buffer.from('hello world')).digest();
});
suite.add('biginthash-bigint', () => {
  getHasher(HashType.MD5).update(Buffer.from('hello world')).digestBigInt();
});
suite.add('biginthash-oneshot-bigint', () => {
  hashAsBigInt(HashType.MD5, Buffer.from('hello world'));
});
suite.add('biginthash-oneshot-buffer', () => {
  hashAsBuffer(HashType.MD5, Buffer.from('hello world'));
});
runSuite(suite, 'md5');

// Test the performance of SHA under various schemes
suite = new benchmark.Suite('sha1');
suite.add('node-crypto-buf', () => {
  crypto.createHash('sha1').update(Buffer.from('hello world')).digest();
});
suite.add('node-crypto-bigint', () => {
  toBigIntBE(
      crypto.createHash('sha1').update(Buffer.from('hello world')).digest());
});
suite.add('biginthash-buf', () => {
  getHasher(HashType.SHA1).update(Buffer.from('hello world')).digest();
});
suite.add('biginthash-bigint', () => {
  getHasher(HashType.SHA1).update(Buffer.from('hello world')).digestBigInt();
});
suite.add('biginthash-oneshot-bigint', () => {
  hashAsBigInt(HashType.SHA1, Buffer.from('hello world'));
});
suite.add('biginthash-oneshot-buffer', () => {
  hashAsBuffer(HashType.SHA1, Buffer.from('hello world'));
});
runSuite(suite, 'SHA1');

// Test the performance of SHA256 under various schemes
suite = new benchmark.Suite('sha256');
suite.add('node-crypto-buf', () => {
  crypto.createHash('sha256').update(Buffer.from('hello world')).digest();
});
suite.add('node-crypto-bigint', () => {
  toBigIntBE(
      crypto.createHash('sha256').update(Buffer.from('hello world')).digest());
});
suite.add('biginthash-buf', () => {
  getHasher(HashType.SHA256).update(Buffer.from('hello world')).digest();
});
suite.add('biginthash-bigint', () => {
  getHasher(HashType.SHA256).update(Buffer.from('hello world')).digestBigInt();
});
suite.add('biginthash-oneshot-bigint', () => {
  hashAsBigInt(HashType.SHA256, Buffer.from('hello world'));
});
suite.add('biginthash-oneshot-buffer', () => {
  hashAsBuffer(HashType.SHA256, Buffer.from('hello world'));
});
runSuite(suite, 'SHA256');

// Test the performance of SHA3_256 under various schemes
suite = new benchmark.Suite('sha3_256');
suite.add('sha3-buf', () => {
  keccak('sha3-256').update(Buffer.from('hello world')).digest();
});
suite.add('sha3-bigint', () => {
  toBigIntBE(keccak('sha3-256').update(Buffer.from('hello world')).digest());
});
suite.add('biginthash-buf', () => {
  getHasher(HashType.SHA3_256).update(Buffer.from('hello world')).digest();
});
suite.add('biginthash-bigint', () => {
  getHasher(HashType.SHA3_256)
      .update(Buffer.from('hello world'))
      .digestBigInt();
});
suite.add('biginthash-oneshot-bigint', () => {
  hashAsBigInt(HashType.SHA3_256, Buffer.from('hello world'));
});
suite.add('biginthash-oneshot-buffer', () => {
  hashAsBuffer(HashType.SHA3_256, Buffer.from('hello world'));
});
runSuite(suite, 'SHA3_256');