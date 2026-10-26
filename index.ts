/**
 * cloak-pro-nopatch — unlimited concurrent sessions for an **already patched**
 * CloakBrowser Pro build, without touching the browser installation.
 *
 * Read-only sibling of `cloak-pro-unlimited`: it never writes, renames, copies
 * or deletes anything inside the browser folder (no patching, no `.orig`). It
 * only verifies that the lease signature gate is already bypassed, then runs an
 * in-process license API that every launch points at.
 *
 * @example
 * import { launch } from 'cloak-pro-nopatch';
 *
 * const browser = await launch({
 *     headless: false,
 *     licenseKey: process.env.CB_KEY,
 *     browserDir: 'D:\\packages\\chromium-155.0.8059.39.1-pro',
 * });
 */
import { resolveBrowser } from './src/resolve.js';
import { createLicenseServer } from './src/server.js';
import {
    KNOWN_PROFILES, describeInstall, discoverSites, findPubkeyVa, inspectBrowser, snapshotBrowser,
} from './src/inspect.js';
import { EXIT_HINTS, explainLaunchError } from './src/errors.js';
import type { Browser, BrowserContext } from 'playwright-core';
import type {
    BinarySnapshot, LicenseServer, NoPatchContextOptions, NoPatchLaunchOptions,
    NoPatchPersistentOptions, PreparedRuntime, PrepareOptions, ResolveOptions, RuntimeControls,
    StatusReport,
} from './src/types.js';
import type { LaunchFailure } from './src/errors.js';

export {
    createLicenseServer, inspectBrowser, discoverSites, snapshotBrowser,
    describeInstall, findPubkeyVa, KNOWN_PROFILES, EXIT_HINTS, explainLaunchError,
};
export type { LaunchFailure };
export * from './src/types.js';

// ---------------------------------------------------------------------------
// Prepared state: one license API per process, one entry per build selector
// ---------------------------------------------------------------------------

interface State {
    preparations: Map<string, Promise<PreparedRuntime>>;
    prepared: PreparedRuntime | null;
    server: LicenseServer | null;
    apiBase: string | null;
}

const STATE: State = { preparations: new Map(), prepared: null, server: null, apiBase: null };

function selectorKey(options: ResolveOptions): string {
    if (options.binaryPath) return `bin:${options.binaryPath}`;
    if (options.browserDir) return `dir:${options.browserDir}`;
    return 'auto';
}

/**
 * Resolve the build, verify it is already patched, start the local license API.
 * Read-only with respect to the browser installation. Cached per build selector.
 */
export function prepare(options: PrepareOptions = {}): Promise<PreparedRuntime> {
    const key = selectorKey(options);
    let pending = STATE.preparations.get(key);
    if (!pending) {
        pending = prepareOnce(options).catch((error: unknown) => {
            STATE.preparations.delete(key);
            throw error;
        });
        STATE.preparations.set(key, pending);
    }
    return pending;
}

async function prepareOnce(options: PrepareOptions): Promise<PreparedRuntime> {
    const {
        licenseKey, browserVersion, releaseChannel, binaryPath, browserDir,
        plan = 'business',
        requirePatched = true,
        log = () => {},
    } = options;

    const browser = await resolveBrowser({ licenseKey, browserVersion, releaseChannel, binaryPath, browserDir });
    const inspection = inspectBrowser(browser.dll);
    const snapshot = snapshotBrowser(browser.dll);

    log(`browser: ${browser.exe} (${browser.source}, tier=${browser.tier})`);
    log(`chrome.dll: ${inspection.hash.slice(0, 16)}… (read-only check, not written)`);

    if (inspection.noLicenseRuntime) {
        log('this build carries no license runtime (free build) — nothing to bypass, API unused');
    } else if (inspection.patched) {
        log(`lease signature gate already bypassed (${inspection.plan?.source ?? 'unknown'})`);
    } else if (requirePatched) {
        throw new Error(
            `this build still verifies the lease signature (${inspection.sites.length} unpatched site(s), `
            + `${inspection.plan?.source ?? 'no plan'}) — it would reject the local lease. Use the patched `
            + 'build you packaged, or pass requirePatched: false if your bypass lives elsewhere',
        );
    } else {
        log('warning: signature gate looks unpatched (requirePatched: false) — launches may fail with exit code 78');
    }

    const server = STATE.server ?? await createLicenseServer({ plan, log });
    STATE.server = server;
    STATE.apiBase = server.url;

    const prepared: PreparedRuntime = {
        browser,
        apiBase: server.url,
        plan,
        inspection: {
            sha256: inspection.hash,
            noLicenseRuntime: inspection.noLicenseRuntime,
            patched: inspection.patched,
            verifyVa: inspection.plan?.verifyVa != null ? `0x${inspection.plan.verifyVa.toString(16)}` : null,
            siteSource: inspection.plan?.source ?? null,
            sites: inspection.sites.map(site => ({ va: `0x${site.va.toString(16)}`, patched: site.patched })),
        },
        snapshot,
        readOnly: true,
    };
    STATE.prepared = prepared;
    return prepared;
}

/** Hash the DLL again and fail loudly if anything changed it. */
export function verifyUnmodified(snapshot: BinarySnapshot): void {
    const now = snapshotBrowser(snapshot.dllPath);
    if (now.sha256 !== snapshot.sha256 || now.size !== snapshot.size) {
        throw new Error(
            `browser installation changed: sha256 ${snapshot.sha256.slice(0, 16)}… -> ${now.sha256.slice(0, 16)}… `
            + `(${snapshot.size} -> ${now.size} bytes)`,
        );
    }
}

// ---------------------------------------------------------------------------
// Launching
// ---------------------------------------------------------------------------

/** Options this module understands; anything else is forwarded to cloakbrowser. */
type CallOptions = RuntimeControls & ResolveOptions & { launchOptions?: Record<string, unknown> };

/**
 * Prepare the selected build, then point the wrapper at it for one launch:
 * `CLOAKBROWSER_LICENSE_API` -> local API, `executablePath` /
 * `CLOAKBROWSER_BINARY_PATH` -> this build. Nothing is written to disk.
 */
async function run<O extends CallOptions, T>(
    options: O,
    exec: (cb: typeof import('cloakbrowser'), shaped: O) => Promise<T>,
): Promise<T> {
    const { plan, requirePatched, assertUnmodified, log, binaryPath, browserDir } = options;
    const prepared = await prepare({
        licenseKey: options.licenseKey,
        browserVersion: options.browserVersion,
        releaseChannel: options.releaseChannel,
        binaryPath, browserDir, plan, requirePatched, log,
    });

    process.env.CLOAKBROWSER_LICENSE_API = prepared.apiBase;
    // Keeps the wrapper from calling ensureBinary() (it would reject a fake key
    // and could pick a different, possibly unpatched, build).
    process.env.CLOAKBROWSER_BINARY_PATH = prepared.browser.exe;

    const launchOptions: Record<string, unknown> = { ...(options.launchOptions ?? {}) };
    launchOptions['executablePath'] ??= prepared.browser.exe;
    const userEnv = launchOptions['env'];
    if (userEnv && typeof userEnv === 'object') {
        launchOptions['env'] = { ...(userEnv as Record<string, string>), CLOAKBROWSER_LICENSE_API: prepared.apiBase };
    }

    const result = await exec(await import('cloakbrowser'), { ...options, launchOptions });
    if (assertUnmodified) verifyUnmodified(prepared.snapshot);
    return result;
}

/** @see import('cloakbrowser').launch */
export function launch(options: NoPatchLaunchOptions = {}): Promise<Browser> {
    return run(options, (cb, shaped) => cb.launch(shaped));
}

/** @see import('cloakbrowser').launchContext */
export function launchContext(options: NoPatchContextOptions = {}): Promise<BrowserContext> {
    return run(options, (cb, shaped) => cb.launchContext(shaped));
}

/** @see import('cloakbrowser').launchPersistentContext */
export function launchPersistentContext(options: NoPatchPersistentOptions): Promise<BrowserContext> {
    return run(options, (cb, shaped) => cb.launchPersistentContext(shaped));
}

// ---------------------------------------------------------------------------
// Introspection / lifecycle
// ---------------------------------------------------------------------------

/** Read-only report: build, patch state, whether the install is unchanged. */
export async function status(options: ResolveOptions = {}): Promise<StatusReport> {
    const browser = await resolveBrowser(options);
    let unchangedSincePrepare: boolean | null = null;
    if (STATE.prepared?.browser.dll === browser.dll) {
        try {
            verifyUnmodified(STATE.prepared.snapshot);
            unchangedSincePrepare = true;
        } catch {
            unchangedSincePrepare = false;
        }
    }
    return {
        browser,
        apiBase: STATE.apiBase,
        serverRunning: Boolean(STATE.server),
        unchangedSincePrepare,
        dll: inspectBrowser(browser.dll),
    };
}

/** Quick boolean: is this build's signature gate already bypassed? */
export async function isPatched(options: ResolveOptions = {}): Promise<boolean> {
    const browser = await resolveBrowser(options);
    const inspection = inspectBrowser(browser.dll);
    return inspection.noLicenseRuntime || inspection.patched;
}

/** Stop the in-process license API and forget prepared builds. Writes nothing. */
export async function shutdown(): Promise<void> {
    if (STATE.server) await STATE.server.close();
    STATE.server = null;
    STATE.apiBase = null;
    STATE.preparations.clear();
    STATE.prepared = null;
}

/** Currently prepared runtime, if `prepare()` has completed. */
export function current(): PreparedRuntime | null {
    return STATE.prepared;
}

export default {
    launch, launchContext, launchPersistentContext,
    prepare, status, isPatched, verifyUnmodified, shutdown, current, describeInstall,
    explainLaunchError,
};
