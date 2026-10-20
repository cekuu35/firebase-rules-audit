#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function stripComments(src) {
  return String(src)
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/\/\/[^\n]*/g, ' ');
}

function braceMatchFrom(src, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function extractServiceBlocks(src, out) {
  const re = /service\s+(cloud\.firestore|firebase\.storage)\s*\{/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    const end = braceMatchFrom(src, m.index + m[0].length - 1);
    if (end === -1) continue;
    out.push({ service: m[1] === 'cloud.firestore' ? 'firestore' : 'storage', body: src.slice(m.index + m[0].length, end) });
  }
}

const MATCH_RE = /match\s+((?:\/[^\s{}]+|\{[^{}\s]+\})+)\s*\{/g;

function stripMatches(src) {
  let s = src;
  for (;;) {
    const re = new RegExp(MATCH_RE.source);
    const m = re.exec(s);
    if (!m) return s;
    const openIdx = m.index + m[0].length - 1;
    const end = braceMatchFrom(s, openIdx);
    if (end === -1) return s;
    s = s.slice(0, m.index) + ' '.repeat(end + 1 - m.index) + s.slice(end + 1);
  }
}

function extractMatches(src, out, depthChain) {
  let pos = 0;
  for (;;) {
    MATCH_RE.lastIndex = pos;
    const m = MATCH_RE.exec(src);
    if (!m) return;
    const pathStr = m[1];
    const openIdx = m.index + m[0].length - 1;
    const end = braceMatchFrom(src, openIdx);
    if (end === -1) return;
    const innerBody = src.slice(openIdx + 1, end);
    const chain = depthChain ? depthChain + ' > ' + pathStr : pathStr;
    out.push({ path: chain, body: stripMatches(innerBody) });
    extractMatches(innerBody, out, chain);
    pos = end + 1;
  }
}

function parseAllows(body) {
  const allows = [];
  const re = /allow\s+([a-z,\s]+?)\s*:\s*if\s+([^;]+);/g;
  let m;
  while ((m = re.exec(body)) !== null) {
    const verbs = m[1].split(',').map((v) => v.trim()).filter(Boolean);
    allows.push({ verbs, cond: m[2].trim() });
  }
  return allows;
}

function auditVersion(src, findings) {
  const vm = /rules_version\s*=\s*'([^']+)'\s*;/.exec(src);
  if (!vm) {
    findings.push({
      rule: 'RULES_VERSION_MISSING', severity: 'low',
      detail: "no rules_version declaration; v1 semantics apply, v2 features (list/album rules) misbehave silently",
      evidence: '(missing)',
    });
  } else if (vm[1] !== '2') {
    findings.push({
      rule: 'LEGACY_RULES_VERSION', severity: 'low',
      detail: "rules_version is '" + vm[1] + "'; v2 has been current since 2020",
      evidence: "rules_version = '" + vm[1] + "'",
    });
  }
}

function auditBlock(block, service, findings) {
  for (const allow of parseAllows(block.body)) {
    const loc = service + ' ' + block.path + ' [' + allow.verbs.join(', ') + ']';
    if (/^true$/.test(allow.cond)) {
      findings.push({
        rule: 'OPEN_ACCESS', severity: 'critical',
        detail: 'allow ' + allow.verbs.join(', ') + ': if true — anyone, no conditions, on ' + block.path,
        evidence: 'allow ' + allow.verbs.join(', ') + ': if true;',
      });
      continue;
    }
    if (/request\.auth\s*==\s*null/.test(allow.cond)) {
      findings.push({
        rule: 'ANON_GRANTED', severity: 'high',
        detail: 'condition explicitly grants unauthenticated requests on ' + block.path,
        evidence: allow.cond.slice(0, 100),
      });
      continue;
    }
    if (!/request\.auth/.test(allow.cond)) {
      findings.push({
        rule: 'NO_AUTH_CHECK', severity: 'high',
        detail: 'allow ' + allow.verbs.join(', ') + ' on ' + block.path + ' has no request.auth reference — unauthenticated clients pass this condition',
        evidence: allow.cond.slice(0, 100),
      });
    }
  }
}

function scanFile(filePath, raw) {
  const src = stripComments(raw);
  const services = [];
  extractServiceBlocks(src, services);
  const findings = [];
  auditVersion(src, findings);
  let blockCount = 0;
  for (const svc of services) {
    const blocks = [];
    extractMatches(svc.body, blocks, null);
    blockCount += blocks.length;
    for (const b of blocks) {
      auditBlock({ path: b.path, body: b.body }, svc.service, findings);
    }
  }
  return { file: filePath, service: services.map((s) => s.service).join('+') || '?', blocks: blockCount, findings };
}

function defaultPaths() {
  const candidates = [
    path.join(process.cwd(), 'firestore.rules'),
    path.join(process.cwd(), 'storage.rules'),
    path.join(process.cwd(), 'rules', 'firestore.rules'),
    path.join(process.cwd(), 'rules', 'storage.rules'),
  ];
  return [...new Set(candidates)].filter((p) => fs.existsSync(p));
}

function printReport(results) {
  const lines = [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const res of results) {
    lines.push('');
    lines.push('== ' + res.file + ' (' + res.service + ', ' + res.blocks + ' match blocks)');
    for (const f of res.findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
      lines.push('   [' + f.severity.toUpperCase() + '] ' + f.rule);
      lines.push('       ' + f.detail);
      lines.push('       evidence: ' + f.evidence);
    }
  }
  return { text: lines.join('\n'), counts };
}

function main(argv) {
  const json = argv.includes('--json');
  const paths = argv.filter((a) => !a.startsWith('--'));
  const targets = paths.length > 0 ? paths : defaultPaths();
  if (targets.length === 0) {
    console.error('No .rules files found. Pass paths explicitly, e.g.: firebase-rules-audit firestore.rules storage.rules');
    return 2;
  }
  const results = [];
  for (const file of targets) {
    try {
      results.push(scanFile(file, fs.readFileSync(file, 'utf8')));
    } catch (e) {
      results.push({ file, service: '?', blocks: 0, findings: [], error: 'unreadable: ' + e.message });
    }
  }
  if (json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    const { text, counts } = printReport(results);
    console.log(text);
    console.log('');
    console.log('Summary: ' + counts.critical + ' critical, ' + counts.high + ' high, ' + counts.medium + ' medium, ' + counts.low + ' low');
  }
  const blocking = results.some((r) => r.findings.some((f) => f.severity === 'critical' || f.severity === 'high'));
  return blocking ? 1 : 0;
}

if (require.main === module) {
  process.exit(main(process.argv.slice(2)));
}

module.exports = { scanFile, extractMatches, extractServiceBlocks, parseAllows, auditVersion, main };
