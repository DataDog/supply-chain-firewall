const fs = require('fs');
const path = require('path');
const project = process.argv[2];
const packages = [];
function walk(directory) {
  if (!fs.existsSync(directory)) return;
  for (const name of fs.readdirSync(directory).sort()) {
    if (name.startsWith('.')) continue;
    const entry = path.join(directory, name);
    if (name.startsWith('@')) { walk(entry); continue; }
    const metadata = path.join(entry, 'package.json');
    if (!fs.existsSync(metadata)) continue;
    const pkg = JSON.parse(fs.readFileSync(metadata, 'utf8'));
    const local = fs.lstatSync(entry).isSymbolicLink() || pkg.name.startsWith('scfw-e2e-');
    packages.push({path:path.relative(project, entry).split(path.sep).join('/'), name:pkg.name, version:pkg.version, local});
    // Do not follow local links: the test only observes the root installation.
    if (!local) walk(path.join(entry, 'node_modules'));
  }
}
walk(path.join(project, 'node_modules'));
// Inspect selected nested installations without following local links.
for (const member of process.argv.slice(3)) walk(path.join(project, member, 'node_modules'));
process.stdout.write(JSON.stringify(packages.sort((a,b) => a.path.localeCompare(b.path))) + '\n');
