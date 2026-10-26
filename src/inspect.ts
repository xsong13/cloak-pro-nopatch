/**
 * Read-only inspection of a CloakBrowser Pro build.
 *
 * Everything here opens the DLL with `'r'` and only reads. There is no write,
 * rename, copy or unlink in this file — by design: this package consumes an
 * already-patched browser and must never touch it.
 *
 * Detection strategy (version and state independent)
 * --------------------------------------------------
 * The license runtime verifies the server's Ed25519 signature over the lease
 * token. Assembly shape, in every build seen so far:
 *
 *     lea  r9, [rip + <32-byte server public key>]   ; 4th argument
 *     mov  rcx, <sig>                                ; 1-2 instructions
 *     mov  r8,  <msg>
 *     call ED25519_verify      <-- or, once patched: b8 01 00 00 00 (mov eax,1)
 *     cmp  eax, 1
 *     jne  <deny>              <-- or sete reg
 *
 * Hunting for `call` instructions breaks on an already patched build (they are
 * gone). So we anchor on the *public key blob* instead: it sits exactly 0x20
 * bytes before the `/api/license/session/end` string, and each
 * `lea r9, [rip+pubkey]` is followed within a few bytes by the 5-byte slot.
 * That slot is either `E8 rel32` (untouched) or `B8 01 00 00 00` (bypassed),
 * which recognises both states on any build — including builds patched by a
 * different tool or by an earlier version of this project.
 */
import fs from 'node:fs';
import {
    readPeLayout, section, vaToFileOffset, sha256File, findStringVa,
    findRipRefsTo, readAt,
} from './pe.js';
import type {
    BinarySnapshot, BrowserInspection, InspectPlan, KnownProfile, PeLayout, SiteState,
} from './types.js';

/** `mov eax, 1`. */
const PATCH_BYTES = Buffer.from([0xb8, 0x01, 0x00, 0x00, 0x00]);
const CALL_OPCODE = 0xe8;
const PATCHED_OPCODE = 0xb8;

const START_PATH_STRING = '/api/license/session/start';
const END_PATH_STRING = '/api/license/session/end';
/** The 32-byte Ed25519 public key occupies the bytes right before this string. */
const PUBKEY_BACKOFF = 0x20;
/** How far past `lea r9, [rip+pubkey]` the 5-byte verification slot can sit. */
const SLOT_SCAN_BYTES = 24;

/**
 * Known Pro builds, keyed by the SHA-256 of the *unpatched* DLL. A patched DLL
 * no longer matches the hash, which is why `profileFits()` also validates the
 * profile structurally.
 */
export const KNOWN_PROFILES: Readonly<Record<string, KnownProfile>> = {
    // chromium-154.0.8037.57.1-pro
    '8a9f1e9020bac1f4c19b5bd8b7fba8e6f8432d2c4755bf5539afbecb1ec9f18f': {
        version: '154.0.8037.57.1',
        verifyVa: 0x1888c3010,
        sites: [0x18938c10a, 0x18938d656, 0x18938e143, 0x18938ed00],
    },
    // chromium-155.0.8059.39.1-pro
    '336f3af913c2a3cdbc6679ada4550ff04b80e27ade54a6c8d8fbb64c9877ff74': {
        version: '155.0.8059.39.1',
        verifyVa: 0x188b3eb50,
        sites: [0x18960dfba, 0x18960f520, 0x18961000d, 0x189610c20],
    },
};

function parseSiteList(value: string): number[] {
    return value.split(/[,\s]+/).filter(Boolean)
        .map(s => Number(s.startsWith('0x') ? s : `0x${s}`));
}

/** VA of the embedded 32-byte server public key, or null when absent. */
export function findPubkeyVa(fd: number, layout: PeLayout): number | null {
    const endVa = findStringVa(fd, layout, '.rdata', END_PATH_STRING);
    if (endVa == null) return null;
    const pubVa = endVa - PUBKEY_BACKOFF;
    const off = vaToFileOffset(pubVa, layout);
    if (off == null) return null;
    const blob = readAt(fd, off, 32);
    if (blob.length !== 32) return null;
    if (blob.every(byte => byte === 0)) return null; // not a key
    return pubVa;
}

interface Slot {
    va: number;
    patched: boolean;
    verifyVa: number | null;
}

/** The 5-byte verification slot following one `lea r9, [rip+pubkey]`. */
function slotAfterLea(fd: number, leaFileOffset: number, leaVa: number): Slot | null {
    const window = readAt(fd, leaFileOffset + 7, SLOT_SCAN_BYTES);
    for (let i = 0; i + 5 <= window.length; i++) {
        const va = leaVa + 7 + i;
        if (window[i] === CALL_OPCODE) {
            return { va, patched: false, verifyVa: va + 5 + window.readInt32LE(i + 1) };
        }
        if (window[i] === PATCHED_OPCODE && window.readInt32LE(i + 1) === 1) {
            return { va, patched: true, verifyVa: null };
        }
    }
    return null;
}

/**
 * Version- and state-independent site discovery: anchor on the public key and
 * follow every `lea r9, [rip+pubkey]` to its verification slot. Works on an
 * untouched build (`E8` slots) and on an already bypassed one (`mov eax,1`).
 */
export function discoverSites(fd: number, layout: PeLayout): InspectPlan | null {
    const pubVa = findPubkeyVa(fd, layout);
    if (pubVa == null) return null; // no license runtime (free build)
    const text = section(layout, '.text');
    if (!text) return null;

    const refs = findRipRefsTo(fd, layout, pubVa);
    if (!refs.length) return null;

    const slots: Slot[] = [];
    for (const refOff of refs) {
        if (refOff < text.rawPtr || refOff >= text.rawPtr + text.rawSize) continue;
        const leaVa = layout.imageBase + text.va + (refOff - text.rawPtr);
        const slot = slotAfterLea(fd, refOff, leaVa);
        if (slot) slots.push(slot);
    }
    if (!slots.length) return null;

    const seen = new Set<number>();
    const unique = slots.filter(slot => (seen.has(slot.va) ? false : (seen.add(slot.va), true)));
    const verifyVa = unique.find(slot => slot.verifyVa != null)?.verifyVa ?? null;
    const patchedCount = unique.filter(slot => slot.patched).length;

    return {
        verifyVa,
        sites: unique.map(slot => slot.va).sort((a, b) => a - b),
        source: `pubkey-discovery (${patchedCount}/${unique.length} patched)`,
        discovered: true,
        anchorVa: pubVa,
    };
}

/** Every site of the profile is either already patched or a call to `verifyVa`. */
function profileFits(fd: number, layout: PeLayout, profile: KnownProfile): boolean {
    for (const va of profile.sites) {
        const off = vaToFileOffset(va, layout);
        if (off == null) return false;
        const cur = readAt(fd, off, 5);
        if (cur.equals(PATCH_BYTES)) continue;
        if (cur[0] !== CALL_OPCODE) return false;
        if (va + 5 + cur.readInt32LE(1) !== profile.verifyVa) return false;
    }
    return true;
}

function choosePlan(fd: number, layout: PeLayout, hash: string): InspectPlan | null {
    const envSites = process.env.CLOAK_PATCH_SITES;
    if (envSites) {
        return {
            verifyVa: process.env.CLOAK_VERIFY_VA ? Number(process.env.CLOAK_VERIFY_VA) : null,
            sites: parseSiteList(envSites),
            source: 'env:CLOAK_PATCH_SITES',
        };
    }
    const byHash = KNOWN_PROFILES[hash];
    if (byHash) return { ...byHash, source: `known:${byHash.version} (sha256)` };

    for (const profile of Object.values(KNOWN_PROFILES)) {
        if (profileFits(fd, layout, profile)) {
            return { ...profile, source: `known:${profile.version} (structural, patched)` };
        }
    }
    return discoverSites(fd, layout);
}

/** Read-only report about one chrome.dll. Never writes, never creates a backup. */
export function inspectBrowser(dllPath: string): BrowserInspection {
    const stat = fs.statSync(dllPath);
    const fd = fs.openSync(dllPath, 'r');
    try {
        const layout = readPeLayout(fd);
        const hash = sha256File(dllPath);
        const plan = choosePlan(fd, layout, hash);
        const backupExists = fs.existsSync(`${dllPath}.orig`);

        if (!plan) {
            const hasLicense = findStringVa(fd, layout, '.rdata', START_PATH_STRING) != null;
            return {
                dllPath, hash, size: stat.size, mtimeMs: stat.mtimeMs,
                noLicenseRuntime: !hasLicense, patched: false,
                plan: null, sites: [], conflicts: [], backupExists,
            };
        }

        const sites: SiteState[] = plan.sites.map(va => {
            const fileOffset = vaToFileOffset(va, layout);
            if (fileOffset == null) throw new Error(`inspected site 0x${va.toString(16)} is not mapped`);
            const current = readAt(fd, fileOffset, 5);
            const isCall = current[0] === CALL_OPCODE;
            return {
                va,
                fileOffset,
                bytes: current.toString('hex'),
                patched: current.equals(PATCH_BYTES),
                isCall,
                targetVa: isCall ? va + 5 + current.readInt32LE(1) : null,
            };
        });
        const conflicts = sites.filter(s =>
            !s.patched && !(s.isCall && (plan.verifyVa == null || s.targetVa === plan.verifyVa)));

        return {
            dllPath, hash, size: stat.size, mtimeMs: stat.mtimeMs,
            noLicenseRuntime: false,
            patched: sites.length > 0 && sites.every(s => s.patched),
            plan, sites, conflicts, backupExists,
        };
    } finally {
        fs.closeSync(fd);
    }
}

/** Minimal snapshot for proving the install stayed bit-identical. */
export function snapshotBrowser(dllPath: string): BinarySnapshot {
    const stat = fs.statSync(dllPath);
    return { dllPath, sha256: sha256File(dllPath), size: stat.size, mtimeMs: stat.mtimeMs };
}

/**
 * Readable / writable check for the DLL. Informational only: this package never
 * writes, but a read-only install is a common reason the *other* tooling fails.
 */
export function describeInstall(browser: { dll: string }): { exists: boolean; writable: boolean } {
    try {
        fs.accessSync(browser.dll, fs.constants.R_OK);
    } catch {
        return { exists: false, writable: false };
    }
    try {
        fs.accessSync(browser.dll, fs.constants.W_OK);
        return { exists: true, writable: true };
    } catch {
        return { exists: true, writable: false };
    }
}
