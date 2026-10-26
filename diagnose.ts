// One-shot diagnostic for "works here, fails on another machine".
//
//   node dist/diagnose.js
//   BROWSER_DIR=D:\packages\chromium-154.0.8037.57.1-pro node dist/diagnose.js
//   DEBUG=pw:browser* node dist/diagnose.js        # plus driver logs
//
// Prints: environment, browser folder inventory, chrome.dll patch state,
// local license API health, a real launch attempt with the decoded failure,
// and the license denial files the binary left behind.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
    launch, shutdown, status, explainLaunchError, describeInstall,
} from './index.js';

const LICENSE_KEY = process.env.CB_KEY || 'cb_local_dev';
const BROWSER_DIR = process.env.BROWSER_DIR; // optional

const line = (label: string, value: unknown): void => {
    console.log(`${label.padEnd(28)}${String(value)}`);
};
const section = (title: string): void => {
    console.log(`\n=== ${title} ${'='.repeat(Math.max(0, 60 - title.length))}`);
};

const failures: string[] = [];
const warn = (message: string): void => { failures.push(message); console.log('  !! ' + message); };

// --------------------------------------------------------------------------- 1
section('environment');
line('node', process.version);
line('platform', `${process.platform} ${process.arch} (${os.release()})`);
line('cpu', `${os.cpus()[0]?.model ?? 'unknown'} x${os.cpus().length}`);
line('memory', `${Math.round(os.totalmem() / 2 ** 30)} GiB`);
line('cwd', process.cwd());
line('license key', `${LICENSE_KEY.slice(0, 6)}… (${LICENSE_KEY.length} chars)`);
line('BROWSER_DIR', BROWSER_DIR ?? '(auto)');
line('CLOAKBROWSER_BINARY_PATH', process.env.CLOAKBROWSER_BINARY_PATH ?? '(unset)');

// --------------------------------------------------------------------------- 2
section('browser resolution');
let report;
try {
    report = await status({ browserDir: BROWSER_DIR, licenseKey: LICENSE_KEY });
} catch (error) {
    console.log('cannot resolve a browser build:');
    console.log(String(error instanceof Error ? error.message : error));
    process.exit(1);
}
line('exe', report.browser.exe);
line('source', report.browser.source);
line('tier', report.browser.tier);
line('dir', path.dirname(report.browser.exe));
const install = describeInstall(report.browser);
line('dll readable', install.exists);
line('dll writable', `${install.writable} (informational: this module never writes)`);

// --------------------------------------------------------------------------- 3
section('folder inventory');
const REQUIRED = [
    'chrome.exe', 'chrome.dll', 'chrome_elf.dll', 'icudtl.dat', 'resources.pak',
    'v8_context_snapshot.bin', 'chrome_100_percent.pak', 'locales/en-US.pak',
];
const OPTIONAL = ['libEGL.dll', 'libGLESv2.dll', 'vk_swiftshader.dll', 'vulkan-1.dll', 'chrome_wer.dll'];
const folder = path.dirname(report.browser.exe);
for (const name of REQUIRED) {
    const ok = fs.existsSync(path.join(folder, name));
    line(`  ${name}`, ok ? 'ok' : 'MISSING');
    if (!ok) warn(`required file missing: ${name} — the copied folder is incomplete`);
}
const missingOptional = OPTIONAL.filter(name => !fs.existsSync(path.join(folder, name)));
line('  optional missing', missingOptional.length ? missingOptional.join(', ') : 'none');
const entries = fs.readdirSync(folder).length;
line('  entries in folder', entries);

// --------------------------------------------------------------------------- 4
section('chrome.dll patch state');
line('sha256', report.dll.hash);
line('patched', report.dll.patched);
line('no license runtime', report.dll.noLicenseRuntime);
line('site source', report.dll.plan?.source ?? '(none)');
line('verify routine', report.dll.plan?.verifyVa != null ? `0x${report.dll.plan.verifyVa.toString(16)}` : '(unknown)');
line('sites', report.dll.sites
    .map(site => `0x${site.va.toString(16)}:${site.patched ? 'patched' : site.bytes}`)
    .join(' ') || '(none)');
line('chrome.dll.orig', report.dll.backupExists ? 'present' : 'absent');
if (!report.dll.noLicenseRuntime && !report.dll.patched) {
    warn('this build still verifies the lease signature — launches will fail with exit code 78 '
        + '(package the patched chrome.dll, or use cloak-pro-unlimited once to patch it)');
}
if (report.dll.conflicts.length) {
    warn(`${report.dll.conflicts.length} site(s) contain unexpected bytes: `
        + report.dll.conflicts.map(c => `${c.va}=${c.bytes}`).join(', '));
}

// --------------------------------------------------------------------------- 5
section('local license api');
try {
    const prepared = await (await import('./index.js')).prepare({
        browserDir: BROWSER_DIR, licenseKey: LICENSE_KEY, log: () => {},
    });
    line('url', prepared.apiBase);
    const probe = await fetch(prepared.apiBase + '/api/license/session/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            license_key: LICENSE_KEY,
            install_id: 'diagnose',
            instance_id: 'diagnose-instance',
            platform: 'windows-x64',
            version: 'diagnose',
        }),
    });
    const body = (await probe.json()) as { lease_id?: string; plan?: string };
    line('self probe', `${probe.status} lease=${body.lease_id ?? '-'} plan=${body.plan ?? '-'}`);
} catch (error) {
    warn('local license api failed: ' + String(error instanceof Error ? error.message : error));
}

// --------------------------------------------------------------------------- 6
section('launch attempt');
try {
    const browser = await launch({
        headless: true,
        licenseKey: LICENSE_KEY,
        browserDir: BROWSER_DIR,
        log: message => console.log('  [module] ' + message),
        launchOptions: process.env.DEBUG
            ? { args: ['--enable-logging=stderr', '--v=1'] }
            : undefined,
    });
    const page = await browser.newPage();
    await page.goto('https://example.com', { timeout: 45000 });
    line('version', await browser.version());
    line('page title', JSON.stringify(await page.title()));
    console.log('  launch OK — this machine can run the browser');
    await browser.close();
} catch (error) {
    const failure = explainLaunchError(error);
    console.log('\n  raw error:');
    for (const row of failure.raw.split('\n')) console.log('    ' + row);
    line('  exit code', failure.exitCode ?? '(none)');
    line('  kind', failure.kind);
    line('  hint', failure.hint);
    warn(`launch failed: ${failure.kind}`);
}

// --------------------------------------------------------------------------- 7
section('license denial files');
const denialDir = path.join(os.homedir(), '.cloakbrowser', 'denials');
try {
    const files = fs.readdirSync(denialDir)
        .map(name => ({ name, full: path.join(denialDir, name), mtime: fs.statSync(path.join(denialDir, name)).mtimeMs }))
        .sort((a, b) => b.mtime - a.mtime)
        .slice(0, 5);
    if (!files.length) console.log('  (none)');
    for (const file of files) {
        const code = fs.readFileSync(file.full, 'utf8').trim();
        const hint = explainLaunchError(`process did exit: exitCode=${code}`).hint;
        console.log(`  ${new Date(file.mtime).toLocaleString()}  code=${code}  ${file.name}`);
        console.log(`    -> ${hint}`);
    }
} catch {
    console.log('  (no denials directory)');
}
line('denials dir', denialDir);
line('cache dir writable', (() => {
    const dir = path.join(os.homedir(), '.cloakbrowser');
    try {
        fs.accessSync(dir, fs.constants.W_OK);
        return true;
    } catch {
        return 'NO — exit code 79 territory';
    }
})());

// --------------------------------------------------------------------------- 8
await shutdown();
section('verdict');
if (failures.length) {
    for (const failure of failures) console.log('  * ' + failure);
    console.log('\n  collect: the block above, plus `status()` output from this machine.');
    process.exitCode = 1;
} else {
    console.log('  no problems found on this machine');
}
