// Analysis-only utility. Does not execute the reference application or ship with DCleaner.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

const [root, reaPackage, destination] = process.argv.slice(2);
if (!root || !reaPackage || !destination) throw new Error('Usage: node inspect-shipped-ui.mjs GUI_ROOT REA_PACKAGE OUTPUT_JSON');
const require = createRequire(path.join(path.resolve(reaPackage), 'package.json'));
const { parse } = require('@babel/parser');
const records = [];
const files = fs.readdirSync(path.join(root, 'chunks')).filter(n => n.endsWith('.js'));
for (const name of ['index.js', 'frame.js', ...files.map(n => `chunks/${n}`)]) {
  const bytes = fs.readFileSync(path.join(root, name));
  const source = bytes.toString('utf8');
  const imports = new Set(), routes = new Set(), translations = new Set(), globals = new Set();
  let ast, error = null, nodes = 0;
  try { ast = parse(source, { sourceType: 'module' }); }
  catch (e) { error = e.message; }
  function visit(n) {
    if (!n || typeof n !== 'object') return;
    if (Array.isArray(n)) { for (const child of n) visit(child); return; }
    if (typeof n.type === 'string') nodes++;
    if (n.type === 'ImportDeclaration') imports.add(n.source.value);
    if (n.type === 'ImportExpression' && n.source.type === 'StringLiteral') imports.add(n.source.value);
    if (n.type === 'Identifier' && /^[A-Z][A-Z_0-9]{2,}$/.test(n.name)) globals.add(n.name);
    const literal = n.type === 'StringLiteral' ? n.value : n.type === 'TemplateLiteral' && n.expressions.length === 0 ? n.quasis[0].value.cooked : null;
    if (typeof literal === 'string') {
      if (/^(#?\/)[a-z*:]|^\/$|^\*$/.test(literal) && !literal.includes('<') && literal.length < 150) routes.add(literal);
      if (/^[a-z][a-z0-9-]+\.[a-z0-9.-]+$/.test(literal) && literal.length < 160) translations.add(literal);
    }
    for (const [key, value] of Object.entries(n)) if (!['loc','start','end','extra','comments'].includes(key)) visit(value);
  }
  visit(ast);
  records.push({ path: name, sha256: crypto.createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length, parsed: !error, error, ast_nodes: nodes, imports: [...imports].sort(), routes: [...routes].sort(), translation_keys: [...translations].sort(), globals: [...globals].sort() });
}
const report = { schema: 1, authority: 'shipped-artifact-static-syntax', execution: 'none', limitation: 'Literal routes and imports are syntax facts; presence does not establish reachability, service execution or licensing.', files: records, parsed_files: records.filter(r => r.parsed).length };
fs.mkdirSync(path.dirname(destination), { recursive: true });
fs.writeFileSync(destination, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ files: records.length, parsed: report.parsed_files, failures: records.filter(r => !r.parsed).map(r=>({path:r.path,error:r.error})), route_owners: records.filter(r=>r.routes.length).map(r=>({path:r.path,routes:r.routes})), injected_globals: [...new Set(records.flatMap(r=>r.globals))].sort() }));
