import { execSync } from 'child_process';

const BASELINE_DASHBOARD_FIRST_LOAD_KB = 188;

console.log('Running bundle size regression test...');
const output = execSync('npm run build', { encoding: 'utf-8' });

// Match dashboard route size line: "/dashboard ... [size] kB ... [firstLoad] kB"
const match = output.match(/\/dashboard\s+[\d.]+\s+kB\s+([\d.]+)\s+kB/);

if (!match) {
  console.error('Could not parse /dashboard First Load JS from build output.');
  process.exit(1);
}

const firstLoadKb = parseFloat(match[1]);
console.log(`Measured /dashboard First Load JS: ${firstLoadKb} kB (Baseline: ${BASELINE_DASHBOARD_FIRST_LOAD_KB} kB)`);

if (firstLoadKb > BASELINE_DASHBOARD_FIRST_LOAD_KB) {
  console.error(`PERF REGRESSION: /dashboard First Load JS ${firstLoadKb} kB exceeds baseline ${BASELINE_DASHBOARD_FIRST_LOAD_KB} kB!`);
  process.exit(1);
}

console.log(`PASS: /dashboard First Load JS ${firstLoadKb} kB is within performance budget (< ${BASELINE_DASHBOARD_FIRST_LOAD_KB} kB).`);
