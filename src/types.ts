/**
 * Types for the read-only runtime module.
 *
 * There is deliberately no `PatchReport` / `RevertReport` here: this package
 * never writes to the browser installation, so a patch result cannot exist.
 */
import type { Server } from 'node:http';
import type { Browser, BrowserContext } from 'playwright-core';
import type {
    LaunchOptions,
    LaunchContextOptions,
    LaunchPersistentContextOptions,
} from 'cloakbrowser';

// ---------------------------------------------------------------------------
// PE layout (read-only)
// ---------------------------------------------------------------------------

export interface PeSection {
    name: string;
    size: number;
    /** Section RVA. */
    va: number;
    /** Size on disk. */
    rawSize: number;
    /** File offset of the raw data. */
    rawPtr: number;
}

export interface PeLayout {
    imageBase: number;
    sections: PeSection[];
}

// ---------------------------------------------------------------------------
// Read-only inspection
// ---------------------------------------------------------------------------

/** A build whose site table we know up front: `sites` are the 5-byte slots. */
export interface KnownProfile {
    version: string;
    /** Entry of the signature-verification routine. */
    verifyVa: number;
    sites: number[];
}

export interface InspectPlan {
    /** Null when every slot is already bypassed (no call left to read). */
    verifyVa: number | null;
    sites: number[];
    /** Human-readable origin: `env:…`, `known:…`, `pubkey-discovery (n/m patched)`. */
    source: string;
    /** Set when the plan came from runtime discovery. */
    discovered?: boolean;
    /** VA of the embedded public key (discovery only). */
    anchorVa?: number;
}

export interface SiteState {
    va: number;
    fileOffset: number;
    /** Current 5 bytes at the slot, hex. */
    bytes: string;
    /** Slot carries `mov eax,1`. */
    patched: boolean;
    /** Slot still is a `call`. */
    isCall: boolean;
    targetVa: number | null;
}

export interface BrowserInspection {
    dllPath: string;
    hash: string;
    size: number;
    mtimeMs: number;
    /** Free build: no license runtime at all. */
    noLicenseRuntime: boolean;
    /** Signature gate bypassed in this build (ours or someone else's patch). */
    patched: boolean;
    plan: InspectPlan | null;
    sites: SiteState[];
    /** Slots matching neither "patched" nor the expected call target. */
    conflicts: SiteState[];
    /** `chrome.dll.orig` next to the binary (left by a patching tool). */
    backupExists: boolean;
}

// ---------------------------------------------------------------------------
// Binary resolution
// ---------------------------------------------------------------------------

export interface BrowserLocation {
    exe: string;
    dll: string;
    /** How it was found: `env:…`, `option:…`, `cloakbrowser.ensureBinary`, `scan:…`. */
    source: string;
    tier: 'pro' | 'free';
}

export interface ResolveOptions {
    licenseKey?: string;
    browserVersion?: string;
    releaseChannel?: 'stable' | 'preview';
    /** Explicit chromium executable; wins over `browserDir` and the env var. */
    binaryPath?: string;
    /** Directory holding `chrome.exe` + `chrome.dll`. */
    browserDir?: string;
}

// ---------------------------------------------------------------------------
// License API
// ---------------------------------------------------------------------------

export interface LicenseRequestBody {
    license_key?: string;
    install_id?: string;
    instance_id?: string;
    platform?: string;
    version?: string;
    lease_id?: string;
    k_pub?: string;
}

export interface LicenseGrant {
    valid: true;
    lease_id: string;
    heartbeat_interval_seconds: number;
    lease_ttl_seconds: number;
    plan: string;
    token: string;
}

export interface LicenseServerStats {
    starts: number;
    heartbeats: number;
    ends: number;
    validates: number;
    /** Every lease handed out (released ones removed). */
    leases: Set<string>;
}

export interface LicenseServerOptions {
    /** Plan name written into the lease. Default `business`. */
    plan?: string;
    host?: string;
    port?: number;
    log?: (message: string) => void;
}

export interface LicenseServer {
    server: Server;
    /** Base URL, exported as CLOAKBROWSER_LICENSE_API. */
    url: string;
    port: number;
    stats: LicenseServerStats;
    close(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Module API
// ---------------------------------------------------------------------------

export interface RuntimeControls {
    /** Plan name written into the local lease. Default `business`. */
    plan?: string;
    /**
     * Refuse to run when the build still verifies the lease signature.
     * Default `true` — turn it off only if you know your build is patched in a
     * way this inspector does not recognise.
     */
    requirePatched?: boolean;
    /** Re-hash the DLL after each launch and fail if it changed. Default `false`. */
    assertUnmodified?: boolean;
    log?: (message: string) => void;
}

export type NoPatchLaunchOptions = LaunchOptions & RuntimeControls & ResolveOptions;
export type NoPatchContextOptions = LaunchContextOptions & RuntimeControls & ResolveOptions;
export type NoPatchPersistentOptions = LaunchPersistentContextOptions & RuntimeControls & ResolveOptions;

export interface PrepareOptions extends RuntimeControls, ResolveOptions {}

/** Snapshot used to prove the installation was not touched. */
export interface BinarySnapshot {
    dllPath: string;
    sha256: string;
    size: number;
    mtimeMs: number;
}

export interface PreparedRuntime {
    browser: BrowserLocation;
    apiBase: string;
    plan: string;
    inspection: {
        sha256: string;
        noLicenseRuntime: boolean;
        patched: boolean;
        verifyVa: string | null;
        siteSource: string | null;
        sites: Array<{ va: string; patched: boolean }>;
    };
    snapshot: BinarySnapshot;
    /** Always true — this package has no code path that writes to the install. */
    readOnly: true;
}

export interface StatusReport {
    browser: BrowserLocation;
    apiBase: string | null;
    serverRunning: boolean;
    /** The installation was bit-identical before and after the last launch. */
    unchangedSincePrepare: boolean | null;
    dll: BrowserInspection;
}

export type { Browser, BrowserContext };
export type { LaunchOptions, LaunchContextOptions, LaunchPersistentContextOptions };
