const fs = require('fs');
const path = require('path');
const [project, name, moduleName] = process.argv.slice(2);
const file = path.join(project, 'node_modules', name, 'package.json');
const result = { present: fs.existsSync(file), imported: false };
if (result.present) {
  const metadata = JSON.parse(fs.readFileSync(file, 'utf8'));
  result.name = metadata.name;
  result.version = metadata.version;
  if (moduleName) {
    require(path.join(project, 'node_modules', moduleName));
    result.imported = true;
  }
}
process.stdout.write(JSON.stringify(result) + '\n');
