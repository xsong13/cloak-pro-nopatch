/**
 * Launch-failure decoding.
 *
 * The wrapper only knows four license exit codes; everything else (Windows
 * loader errors, plain crashes) arrives as an opaque Playwright message. These
 * helpers pull the child exit code out of the error chain and say what it
 * usually means, so a failure on someone else's machine is diagnosable from one
 * log line instead of a guessing session.
 */
export type FailureKind =
    | 'license-seat'
    | 'license-key'
    | 'license-verify'
    | 'license-config'
    | 'missing-dll'
    | 'access-violation'
    | 'process-failed'
    | 'not-process-exit'
    | 'unknown';

export interface LaunchFailure {
    /** Full error text, including causes. */
    raw: string;
    /** Child-process exit code when one could be parsed. */
    exitCode: number | null;
    kind: FailureKind;
    /** One-line explanation with the usual root cause. */
    hint: string;
}

/** Where the child exit code hides (Playwright / Puppeteer / .NET drivers). */
const EXIT_PATTERNS: RegExp[] = [
    /process did exit:\s*exitCode=(-?\d+)/i,
    /Failed to launch the browser process:\s*Code:\s*(-?\d+)/i,
    /exited with (?:exit )?code (-?\d+)/i,
    /exitCode=(-?\d+)/i,
];

/** Exit codes the Pro binary and the Windows loader use, and what they mean here. */
export const EXIT_HINTS: Readonly<Record<number, { kind: FailureKind; hint: string }>> = {
    76: {
        kind: 'license-seat',
        hint: 'seat limit: the browser talked to the REAL license server, not the local one — '
            + 'CLOAKBROWSER_LICENSE_API did not reach the child (check launchOptions.env) '
            + 'or this binary is not the patched build',
    },
    77: {
        kind: 'license-key',
        hint: 'license key missing/invalid/expired: pass a non-empty licenseKey — the Pro binary '
            + 'refuses to start without one even when the signature gate is bypassed',
    },
    78: {
        kind: 'license-verify',
        hint: 'lease rejected: the local license API was unreachable from the browser, or this '
            + 'chrome.dll still verifies the lease signature (unpatched copy). status().dll.patched '
            + 'must be true',
    },
    79: {
        kind: 'license-config',
        hint: 'local configuration problem: ~/.cloakbrowser is not writable for the browser user, '
            + 'or an invalid --license-route value was passed',
    },
    [-1073741515]: {
        kind: 'missing-dll',
        hint: '0xC0000135 DLL_NOT_FOUND: the browser folder is incomplete — chrome_elf.dll, '
            + 'resources.pak, icudtl.dat, v8_context_snapshot.bin and locales/ are required',
    },
    [-1073741819]: {
        kind: 'access-violation',
        hint: '0xC0000005 access violation: chrome.dll does not match this chrome.exe / .pak set, '
            + 'or patch bytes were applied to a different build',
    },
    [-1073741701]: {
        kind: 'process-failed',
        hint: '0xC000007B INVALID_IMAGE_FORMAT: 32-bit / 64-bit mismatch inside the folder',
    },
    1: {
        kind: 'process-failed',
        hint: 'generic startup failure: missing pak/resources, a locked user-data-dir, or a bad flag — '
            + 'add launchOptions.args ["--enable-logging=stderr","--v=1"] for details',
    },
};

function collectErrorText(error: unknown): string {
    const parts: string[] = [];
    let current: unknown = error;
    for (let depth = 0; current && depth < 6; depth++) {
        if (current instanceof Error) {
            parts.push(`${current.name}: ${current.message}`);
            current = (current as { cause?: unknown }).cause;
        } else {
            parts.push(String(current));
            break;
        }
    }
    return parts.join('\n  caused by -> ');
}

/** Turn a launch error into a code plus the usual root cause. */
export function explainLaunchError(error: unknown): LaunchFailure {
    const raw = collectErrorText(error);
    let exitCode: number | null = null;
    for (const pattern of EXIT_PATTERNS) {
        const match = raw.match(pattern);
        if (match) {
            exitCode = Number(match[1]);
            break;
        }
    }
    if (exitCode == null) {
        return {
            raw, exitCode: null, kind: 'not-process-exit',
            hint: 'the browser process never produced an exit code — typical causes: executablePath '
                + 'missing or not executable, launch timeout, or the CDP handshake failed. Check that '
                + 'binaryPath/browserDir points at a complete browser folder',
        };
    }
    const known = EXIT_HINTS[exitCode];
    if (known) return { raw, exitCode, ...known };
    return {
        raw, exitCode, kind: 'unknown',
        hint: `unrecognised exit code ${exitCode}: usually a crash inside the browser process. `
            + 'Re-run with launchOptions.args = ["--enable-logging=stderr","--v=1"] and DEBUG=pw:browser*',
    };
}
