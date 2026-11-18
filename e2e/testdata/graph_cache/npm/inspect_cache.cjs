const fs = require('fs');
const path = require('path');
const [executable, cache] = process.argv.slice(2);
const cacache = require(require.resolve('cacache', { paths: [fs.realpathSync(executable)] }));
(async () => {
  const directory = path.join(cache, '_cacache');
  const entries = await cacache.ls(directory);
  const result = [];
  for (const key of Object.keys(entries).sort()) {
    // Reading through npm's own cache verifies the content's recorded digest.
    const content = await cacache.get(directory, key);
    result.push({ key, integrity: content.integrity, size: content.data.length });
  }
  process.stdout.write(JSON.stringify(result) + '\n');
})().catch(error => { console.error(error); process.exitCode = 1; });
