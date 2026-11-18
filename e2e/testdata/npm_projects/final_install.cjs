const fs = require('fs');
const path = require('path');
// Resolution may run lifecycle hooks elsewhere. Assert only the final project.
if (fs.realpathSync(process.cwd()) === fs.realpathSync(process.env.SCFW_E2E_FINAL_PROJECT)) {
  fs.writeFileSync(path.join(process.cwd(), 'final-install.marker'), 'final project postinstall\n');
  if (process.env.SCFW_E2E_FINAL_FAILURE === '1') process.exit(23);
}
