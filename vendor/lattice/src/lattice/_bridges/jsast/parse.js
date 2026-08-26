// JS/TS/JSX -> Babel JSON AST bridge for the arbitrary-call ingest (mirrors solc --ast-compact-json).
// Picks parser plugins by extension so .ts type annotations and .tsx/.jsx all parse.
const { parse } = require('@babel/parser');
const fs = require('fs');
const file = process.argv[2];
const ext = (file.split('.').pop() || '').toLowerCase();
let plugins;
if (ext === 'ts') plugins = ['typescript'];
else if (ext === 'tsx') plugins = ['typescript', 'jsx'];
else plugins = ['jsx'];                 // js, jsx, mjs, cjs — allow JSX, no TS ambiguity
try {
  const ast = parse(fs.readFileSync(file, 'utf8'),
    { sourceType: 'unambiguous', errorRecovery: true, plugins });
  // Babel's recovery mode returns a useful partial AST *and* records syntax errors on
  // the File node. Preserve both: callers can keep tolerant structural enrichment while
  // making every recovered parser error gate-visible instead of reporting a clean graph.
  ast.program.__latticeParserErrors = (ast.errors || []).map((error) => ({
    message: String(error && error.message ? error.message : error),
    code: error && error.code ? String(error.code) : null,
    reasonCode: error && error.reasonCode ? String(error.reasonCode) : null,
    line: error && error.loc && error.loc.line ? Number(error.loc.line) : 1,
    column: error && error.loc && Number.isFinite(error.loc.column) ? Number(error.loc.column) : 0,
  }));
  process.stdout.write(JSON.stringify(ast.program));
} catch (e) { process.stderr.write('PARSE_ERROR: ' + e.message); process.exit(2); }
