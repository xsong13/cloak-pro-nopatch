// Read-only runtime example: launches N concurrent browsers from an already
// patched build and proves the installation was not modified.
//
//   node dist/example.js
//   N=10 HEADED=1 BROWSER_DIR=D:\packages\chromium-154.0.8037.57.1-pro node dist/example.js
import { launch, status, verifyUnmodified, shutdown } from './index.js';

const N = Number(process.env.N || 4);
const HEADED = process.env.HEADED === '1';
const LICENSE_KEY = process.env.CB_KEY || 'cb_local_dev';
const BROWSER_DIR = process.env.BROWSER_DIR; // optional, otherwise auto-resolved

const options = {
    headless: !HEADED,
    licenseKey: LICENSE_KEY,
    browserDir: BROWSER_DIR,
};

const info = await status({ browserDir: BROWSER_DIR });
console.log('dll       :', info.dll.dllPath);
console.log('sha256    :', info.dll.hash);
console.log('patched   :', info.dll.patched, `(${info.dll.plan?.source ?? 'unknown'})`);
console.log('backup    :', info.dll.backupExists ? 'chrome.dll.orig present (not ours)' : 'none');
console.log('');

const browsers = [];
const t0 = Date.now();
try {
    for (let i = 1; i <= N; i++) {
        const browser = await launch(options);
        const page = await browser.newPage();
        await page.goto('https://example.com', { timeout: 45000 });
        browsers.push(browser);
        console.log(`#${String(i).padStart(2)} ${await browser.version()}  "${await page.title()}"`);
    }
    console.log(`\n${browsers.length} concurrent sessions alive after ${((Date.now() - t0) / 1000).toFixed(1)}s`);
} finally {
    for (const browser of browsers) await browser.close().catch(() => {});
    console.log(`closed ${browsers.length}`);
}

const prepared = (await import('./index.js')).current();
if (prepared) {
    verifyUnmodified(prepared.snapshot);
    console.log('installation unchanged (sha256 + size identical)');
}
await shutdown();
