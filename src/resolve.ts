/**
 * Work out which Chromium executable (and therefore which chrome.dll) the
 * cloakbrowser wrapper is going to launch.
 *
 * Order:
 *   1. `binaryPath` option (explicit executable)
 *   2. `browserDir` option (directory holding chrome.exe)
 *   3. CLOAKBROWSER_BINARY_PATH
 *   4. cloakbrowser's own ensureBinary()
 *   5. newest `chromium-*-pro` folder under ~/.cloakbrowser
 *
 * ensureBinary() picks the *free* build when no license key resolves, so its
 * answer is only accepted when it actually points at a Pro build; otherwise an
 * already installed Pro build wins and the free one is only a fallback.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { BrowserLocation, ResolveOptions } from './types.js';

function dllNextTo(exePath: string): string {
    return path.join(path.dirname(exePath), 'chrome.dll');
}

/** A Pro build lives in a `chromium-<ver>-pro` directory. */
function isProBuild(exePath: string): boolean {
    return /-pro$/i.test(path.basename(path.dirname(exePath)));
}

function makeLocation(exe: string, source: string): BrowserLocation {
    const dll = dllNextTo(exe);
    if (!fs.existsSync(dll)) {
        throw new Error(
            `browser folder incomplete: chrome.dll is missing next to ${exe} — `
            + 'copy the whole build directory (chrome.exe + chrome.dll + chrome_elf.dll, '
            + 'resources.pak, icudtl.dat, v8_context_snapshot.bin, locales/), not just the exe',
        );
    }
    return { exe, dll, source, tier: isProBuild(exe) ? 'pro' : 'free' };
}

/**
 * Turn a caller-supplied `binaryPath` / `browserDir` into an executable path.
 * A directory may name the exe `chrome.exe`; a pointer to `chrome.dll` is also
 * accepted and mapped back to its sibling executable.
 */
function fromExplicit(options: ResolveOptions): BrowserLocation | null {
    if (options.binaryPath) {
        const exe = path.resolve(options.binaryPath);
        if (path.basename(exe).toLowerCase() === 'chrome.dll') {
            return fromExplicit({ browserDir: path.dirname(exe) });
        }
        if (!fs.existsSync(exe)) {
            throw new Error(`binaryPath does not exist: ${exe}`);
        }
        return makeLocation(exe, 'option:binaryPath');
    }
    if (options.browserDir) {
        const dir = path.resolve(options.browserDir);
        if (!fs.existsSync(dir)) {
            throw new Error(`browserDir does not exist: ${dir}`);
        }
        for (const name of ['chrome.exe', 'chromium.exe']) {
            const exe = path.join(dir, name);
            if (fs.existsSync(exe)) return makeLocation(exe, 'option:browserDir');
        }
        throw new Error(`browserDir has no chrome.exe: ${dir}`);
    }
    return null;
}

function proDirs(root: string): Array<{ name: string; dir: string; key: number[] }> {
    let entries: fs.Dirent[];
    try {
        entries = fs.readdirSync(root, { withFileTypes: true });
    } catch {
        return [];
    }
    return entries
        .filter(e => e.isDirectory() && /-pro$/i.test(e.name))
        .map(e => {
            const match = e.name.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)/);
            return {
                name: e.name,
                dir: path.join(root, e.name),
                key: match ? match.slice(1).map(Number) : [0, 0, 0, 0],
            };
        })
        .sort((a, b) => {
            for (let i = 0; i < 4; i++) {
                const ai = a.key[i] ?? 0;
                const bi = b.key[i] ?? 0;
                if (ai !== bi) return bi - ai;
            }
            return 0;
        });
}

function installedProBuild(root: string): BrowserLocation | null {
    for (const candidate of proDirs(root)) {
        const exe = path.join(candidate.dir, 'chrome.exe');
        if (fs.existsSync(exe)) return makeLocation(exe, `scan:${candidate.name}`);
    }
    return null;
}

export async function resolveBrowser(options: ResolveOptions = {}): Promise<BrowserLocation> {
    const explicit = fromExplicit(options);
    if (explicit) return explicit;

    const envExe = process.env.CLOAKBROWSER_BINARY_PATH;
    if (envExe && fs.existsSync(envExe)) {
        return makeLocation(envExe, 'env:CLOAKBROWSER_BINARY_PATH');
    }

    let fromWrapper: BrowserLocation | null = null;
    try {
        const cloakbrowser = await import('cloakbrowser');
        if (typeof cloakbrowser.ensureBinary === 'function') {
            const exe = await cloakbrowser.ensureBinary(
                options.licenseKey, options.browserVersion, options.releaseChannel,
            );
            if (exe && fs.existsSync(exe)) fromWrapper = makeLocation(exe, 'cloakbrowser.ensureBinary');
        }
    } catch {
        // Invalid/expired key, or the license server is unreachable — the key is
        // only needed to *obtain* a Pro build, not to run one we already have.
    }

    if (fromWrapper?.tier === 'pro') return fromWrapper;

    const installed = installedProBuild(path.join(os.homedir(), '.cloakbrowser'));
    if (installed) return installed;

    if (fromWrapper) return fromWrapper; // free build is better than nothing

    throw new Error(
        'no CloakBrowser Pro build found — pass binaryPath/browserDir, a valid licenseKey once '
        + '(so ensureBinary can download Pro), or set CLOAKBROWSER_BINARY_PATH',
    );
}
