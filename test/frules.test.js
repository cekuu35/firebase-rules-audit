'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { scanFile, extractMatches, parseAllows } = require('../bin/frules.js');

const ROOT = path.join(__dirname, '..');
const broken = fs.readFileSync(path.join(ROOT, 'examples', 'broken', 'firestore.rules'), 'utf8');
const brokenStore = fs.readFileSync(path.join(ROOT, 'examples', 'broken', 'storage.rules'), 'utf8');
const clean = fs.readFileSync(path.join(ROOT, 'examples', 'clean', 'firestore.rules'), 'utf8');

test('broken firestore rules trigger OPEN_ACCESS, ANON_GRANTED and NO_AUTH_CHECK once each', () => {
  const res = scanFile('firestore.rules', broken);
  const rules = res.findings.map((f) => f.rule);
  assert.strictEqual(rules.filter((r) => r === 'OPEN_ACCESS').length, 2);
  assert.strictEqual(rules.filter((r) => r === 'ANON_GRANTED').length, 1);
  assert.strictEqual(rules.filter((r) => r === 'NO_AUTH_CHECK').length, 1);
  assert.ok(rules.includes('LEGACY_RULES_VERSION'));
});

test('broken storage rules with auth!=null wildcard is not flagged', () => {
  const res = scanFile('storage.rules', brokenStore);
  const blocking = res.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
  assert.strictEqual(blocking.length, 0);
});

test('clean firestore rules produce zero findings', () => {
  const res = scanFile('firestore.rules', clean);
  assert.strictEqual(res.findings.length, 0);
});

test('match paths with bind variables parse fully', () => {
  const blocks = [];
  extractMatches('match /databases/{database}/documents { allow read: if true; }', blocks, null);
  assert.strictEqual(blocks[0].path, '/databases/{database}/documents');
  assert.strictEqual(parseAllows(blocks[0].body).length, 1);
});

test('nested match blocks are not double-reported', () => {
  const src = 'service cloud.firestore { match /a { match /b { allow read: if true; } } }';
  const blocks = [];
  extractMatches(src, blocks, null);
  assert.strictEqual(blocks.length, 2);
  const parentAllows = parseAllows(blocks.find((b) => b.path === '/a').body).length;
  assert.strictEqual(parentAllows, 0);
});

test('clean rules exit code is 0, broken is 1', () => {
  const cleanRes = scanFile('x.rules', clean);
  const brokenRes = scanFile('x.rules', broken);
  const cleanBlocking = cleanRes.findings.some((f) => f.severity === 'critical' || f.severity === 'high');
  const brokenBlocking = brokenRes.findings.some((f) => f.severity === 'critical' || f.severity === 'high');
  assert.strictEqual(cleanBlocking, false);
  assert.strictEqual(brokenBlocking, true);
});
