const fs = require('node:fs'), path = require('node:path');
const root = path.resolve(__dirname, '..', '.github/workflows');
let count = 0;
for (const name of fs.readdirSync(root).filter(name => /\.ya?ml$/.test(name))) {
  const text = fs.readFileSync(path.join(root, name), 'utf8');
  for (const match of text.matchAll(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/gm)) {
    const action = match[1].replace(/^['"]|['"]$/g, '');
    if (!action.startsWith('./') && !/^[\w.-]+\/[\w./-]+@[a-f0-9]{40}$/.test(action)) throw new Error(`${name}: third-party action is not pinned to a full commit: ${action}`);
  }
  count++;
}
const assurance = fs.readFileSync(path.join(root, 'dependency-assurance.yml'), 'utf8');
if (!/\n  schedule:/.test(assurance) || !/\n  baseline-expiry:/.test(assurance)) throw new Error('Scheduled baseline-expiry gate must remain');
const release = fs.readFileSync(path.join(root, 'release.yml'), 'utf8');
for (const platform of ['macos', 'windows']) if (!release.includes(`if: env.PLATFORM_SIGNING == '${platform}'`)) throw new Error(`Missing conditional ${platform} signature gate`);
const pages = fs.readFileSync(path.join(root, 'pages.yml'), 'utf8');
if (/^  release:/m.test(pages)) throw new Error('Pages must not deploy directly from a release tag; its protected environment permits only main');
if (!/^    if: github\.ref == 'refs\/heads\/main'$/m.test(pages)) throw new Error('Pages deployment must be restricted to main');
if (/^concurrency:/m.test(pages) || !/^    concurrency:\n      group: pages\n      cancel-in-progress: true$/m.test(pages)) throw new Error('Pages concurrency must apply only to the permitted deployment job');
// Pull requests skip macOS to save scarce runners, so macOS must still gate
// pushes to main and the nightly run, and superseded main runs must never be
// cancelled.
const desktop = fs.readFileSync(path.join(root, 'desktop-sync-ci.yml'), 'utf8');
const matrix = desktop.match(/^        include: \$\{\{ fromJSON\(github\.event_name == 'pull_request' && '(\[.*?\])' \|\| '(\[.*?\])'\) \}\}$/m);
if (!matrix) throw new Error('Desktop matrix must choose its platforms from the event name');
const names = json => JSON.parse(json).map(entry => entry.name).sort().join(',');
if (names(matrix[1]) !== 'Linux,Windows') throw new Error('Pull requests must build Linux and Windows');
if (names(matrix[2]) !== 'Linux,Windows,macOS,macOS Intel') throw new Error('Pushes, nightly and dispatch runs must build every desktop platform');
if (!/^  push:\n    branches: \[main/m.test(desktop) || !/^  schedule:\n(?:    #.*\n)?    - cron: /m.test(desktop)) throw new Error('Desktop CI must run on pushes to main and nightly');
for (const name of fs.readdirSync(root).filter(name => /\.ya?ml$/.test(name))) {
  const text = fs.readFileSync(path.join(root, name), 'utf8');
  if (!/^  pull_request:/m.test(text)) continue;
  if (!/^concurrency:\n  group: \$\{\{ github\.workflow \}\}-\$\{\{ github\.ref \}\}\n  cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}$/m.test(text)) throw new Error(`${name}: pull request workflows must cancel superseded pull request runs only`);
}
const refresh = release.split('\n  refresh-product-page:\n')[1];
const stableMainDispatch = refresh
  && /^    needs: publish-release$/m.test(refresh)
  && /^    if: \$\{\{ !contains\(github\.ref_name, '-'\) \}\}$/m.test(refresh)
  && /^    permissions:\n      actions: write\n    steps:/m.test(refresh)
  && refresh.includes('github.rest.actions.createWorkflowDispatch')
  && refresh.includes("workflow_id: 'pages.yml'")
  && refresh.includes("ref: 'main'");
if (!stableMainDispatch) throw new Error('Stable desktop publication must explicitly dispatch the protected Pages workflow on main with only actions:write');
console.log(`[workflow-pins] ${count} workflow action pins and scheduled/conditional/deployment protections passed; workflow execution remains UNRUN.`);
