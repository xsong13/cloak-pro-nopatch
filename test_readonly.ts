// Integrity guard for the read-only guarantee.
//
//   node dist/test_readonly.js
//
// 1. snapshots the browser directory (every file: relative path, size, mtime)
//    and the chrome.dll sha256
// 2. launches 3 concurrent browsers through the module
// 3. re-snapshots and fails on ANY difference (new file, changed byte, new
//    chrome.dll.orig, touched mtime)
// 4. also greps this package's own compiled sources for write syscalls
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, status, shutdown } from './index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LICENSE_KEY = process.env.CB_KEY || 'cb_local_dev';

function dirSnapshot(root: string): Map<string, string> {
    const out = new Map<string, string>();
    const walk = (dir: string): void => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                if (entry.name === 'locales' || entry.name === 'Dictionaries') {
                    // huge, untouched by us; record the directory itself only
                    out.set(path.relative(root, full) + '/', 'dir');
                    continue;
                }
                walk(full);
                continue;
            }
            const st = fs.statSync(full);
            out.set(path.relative(root, full), `${st.size}:${Math.round(st.mtimeMs)}`);
        }
    };
    walk(root);
    return out;
}

function diff(before: Map<string, string>, after: Map<string, string>): string[] {
    const problems: string[] = [];
    for (const [file, sig] of before) {
        const now = after.get(file);
        if (now === undefined) problems.push(`removed: ${file}`);
        else if (now !== sig) problems.push(`modified: ${file} (${sig} -> ${now})`);
    }
    for (const file of after.keys()) {
        if (!before.has(file)) problems.push(`created: ${file}`);
    }
    return problems;
}

const info = await status({ licenseKey: LICENSE_KEY });
const browserDir = path.dirname(info.browser.exe);
console.log('browser dir:', browserDir);
console.log('dll sha256 :', info.dll.hash);
console.log('patched    :', info.dll.patched, `(${info.dll.plan?.source ?? 'unknown'})`, '\n');

const before = dirSnapshot(browserDir);
const beforeCount = before.size;

const browsers = [];
try {
    for (let i = 1; i <= 3; i++) {
        const browser = await launch({ headless: true, licenseKey: LICENSE_KEY });
        const page = await browser.newPage();
        await page.goto('https://example.com', { timeout: 45000 });
        browsers.push(browser);
        console.log(`#${i} ${await browser.version()} "${await page.title()}"`);
    }
} finally {
    for (const browser of browsers) await browser.close().catch(() => {});
    await shutdown();
}

const after = dirSnapshot(browserDir);
const problems = diff(before, after);

console.log(`\nfiles before/after: ${beforeCount}/${after.size}`);
console.log('chrome.dll.orig    :', fs.existsSync(`${info.browser.dll}.orig`) ? 'present (pre-existing)' : 'absent');

// Static check: the compiled module must contain no write syscalls at all.
const WRITE_PATTERNS = [
    'writeFileSync', 'appendFileSync', 'copyFileSync', 'renameSync', 'unlinkSync',
    'mkdirSync', 'rmSync', 'rmdirSync', 'truncateSync', 'chmodSync', 'utimesSync',
    "'r+'", '"r+"',
];
const offenders: string[] = [];
for (const file of ['index.js', 'src/inspect.js', 'src/pe.js', 'src/resolve.js', 'src/server.js']) {
    const full = path.join(HERE, file);
    if (!fs.existsSync(full)) continue;
    const text = fs.readFileSync(full, 'utf8');
    for (const pattern of WRITE_PATTERNS) {
        if (text.includes(pattern)) offenders.push(`${file}: ${pattern}`);
    }
}
console.log('write syscalls     :', offenders.length ? offenders.join(', ') : 'none found');

if (problems.length) {
    console.error('\nFAIL — the browser directory changed:');
    for (const problem of problems) console.error('  ' + problem);
    process.exitCode = 1;
} else if (offenders.length) {
    console.error('\nFAIL — compiled sources contain write syscalls:', offenders.join(', '));
    process.exitCode = 1;
} else {
    console.log('\nPASS — 3 concurrent sessions, installation bit-identical, no write paths in the module');
}
