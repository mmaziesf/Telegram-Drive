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
// Cost policy: Linux-only by default, Windows on the 'ci:windows' PR label,
// full matrix only on workflow_dispatch or v* tags; no nightly desktop cron;
// superseded non-main runs are cancelled, main runs never are.
const desktop = fs.readFileSync(path.join(root, 'desktop-sync-ci.yml'), 'utf8');
const matrix = desktop.match(/^        include: \$\{\{ fromJSON\(\(github\.event_name == 'workflow_dispatch' \|\| startsWith\(github\.ref, 'refs\/tags\/v'\)\) && '(\[.*?\])' \|\| \(github\.event_name == 'pull_request' && contains\(github\.event\.pull_request\.labels\.\*\.name, 'ci:windows'\)\) && '(\[.*?\])' \|\| '(\[.*?\])'\) \}\}$/m);
if (!matrix) throw new Error('Desktop matrix must follow the cost policy (dispatch/tag full, ci:windows label, else Linux)');
const names = json => JSON.parse(json).map(entry => entry.name).sort().join(',');
if (names(matrix[1]) !== 'Linux,Windows,macOS,macOS Intel') throw new Error('Dispatch and release tags must build every desktop platform');
if (names(matrix[2]) !== 'Linux,Windows') throw new Error('ci:windows label must add Windows');
if (names(matrix[3]) !== 'Linux') throw new Error('Default desktop build must be Linux only');
if (/^  schedule:/m.test(desktop)) throw new Error('Desktop CI must not run on a schedule');
for (const name of fs.readdirSync(root).filter(name => /\.ya?ml$/.test(name))) {
  const text = fs.readFileSync(path.join(root, name), 'utf8');
  if (/develop/.test(text.split('\njobs:')[0])) throw new Error(`${name}: there is no develop branch`);
  if (/workflow_run:/.test(text)) throw new Error(`${name}: workflow_run chains are not allowed`);
  if (!/^  pull_request:/m.test(text)) continue;
  if (!/^concurrency:\n  group: \$\{\{ github\.workflow \}\}-\$\{\{ github\.ref \}\}\n  cancel-in-progress: \$\{\{ github\.ref != 'refs\/heads\/main' \}\}$/m.test(text)) throw new Error(`${name}: must cancel superseded non-main runs only`);
}
// This fork publishes no releases and no product site: a tag push must not
// start the release pipeline, and no workflow may deploy GitHub Pages.
if (/^  push:/m.test(release.split('\njobs:')[0])) throw new Error('Release must not run on push; it is manual-only until the fork has its own signing identities');
for (const name of fs.readdirSync(root).filter(name => /\.ya?ml$/.test(name))) {
  if (fs.readFileSync(path.join(root, name), 'utf8').includes('actions/deploy-pages')) throw new Error(`${name}: this fork must not deploy the original project's product site`);
}
console.log(`[workflow-pins] ${count} workflow action pins and scheduled/conditional/no-publication protections passed; workflow execution remains UNRUN.`);
