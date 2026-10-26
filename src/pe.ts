/**
 * Minimal PE32+ reader: headers, section mapping, string lookup and RIP-relative
 * reference scanning. Read-only, and streamed in chunks so a 340 MB chrome.dll
 * never has to be loaded whole.
 */
import fs from 'node:fs';
import crypto from 'node:crypto';
import type { PeLayout, PeSection } from './types.js';

const CHUNK = 8 << 20;
const OVERLAP = 16;

/** Read the DOS/NT headers plus the section table. */
export function readPeLayout(fd: number): PeLayout {
    const head = Buffer.alloc(0x1000);
    fs.readSync(fd, head, 0, head.length, 0);
    if (head[0] !== 0x4d || head[1] !== 0x5a) throw new Error('not a PE file (missing MZ)');

    const eLfanew = head.readUInt32LE(0x3c);
    if (readAt(fd, eLfanew, 4).toString('latin1') !== 'PE\0\0') {
        throw new Error('not a PE file (missing PE signature)');
    }

    const coff = eLfanew + 4;
    const numSections = head.readUInt16LE(coff + 2);
    const sizeOfOptional = head.readUInt16LE(coff + 16);
    const opt = coff + 20;
    const magic = head.readUInt16LE(opt);
    if (magic !== 0x20b) throw new Error(`expected PE32+ (x64), got magic 0x${magic.toString(16)}`);

    const imageBase = Number(head.readBigUInt64LE(opt + 24));
    const sections: PeSection[] = [];
    const secOff = opt + sizeOfOptional;
    for (let i = 0; i < numSections; i++) {
        const o = secOff + i * 40;
        sections.push({
            name: head.toString('latin1', o, o + 8).replace(/\0+$/, ''),
            size: head.readUInt32LE(o + 8),
            va: head.readUInt32LE(o + 12),
            rawSize: head.readUInt32LE(o + 16),
            rawPtr: head.readUInt32LE(o + 20),
        });
    }
    return { imageBase, sections };
}

export function section(layout: PeLayout, name: string): PeSection | undefined {
    return layout.sections.find(entry => entry.name === name);
}

/** File offset of a VA, or null when that VA is not backed by file data. */
export function vaToFileOffset(va: number, layout: PeLayout): number | null {
    const rva = va - layout.imageBase;
    for (const entry of layout.sections) {
        if (rva >= entry.va && rva < entry.va + entry.rawSize) return entry.rawPtr + (rva - entry.va);
    }
    return null;
}

function fileOffsetToVa(off: number, layout: PeLayout): number | null {
    for (const entry of layout.sections) {
        if (off >= entry.rawPtr && off < entry.rawPtr + entry.rawSize) {
            return layout.imageBase + entry.va + (off - entry.rawPtr);
        }
    }
    return null;
}

/** Read up to `len` bytes at an absolute file offset. */
export function readAt(fd: number, off: number, len: number): Buffer {
    const buf = Buffer.alloc(len);
    const n = fs.readSync(fd, buf, 0, len, off);
    return buf.subarray(0, n);
}

export function sha256File(file: string): string {
    const hash = crypto.createHash('sha256');
    const fd = fs.openSync(file, 'r');
    try {
        const buf = Buffer.allocUnsafe(1 << 22);
        let pos = 0;
        for (;;) {
            const n = fs.readSync(fd, buf, 0, buf.length, pos);
            if (!n) break;
            hash.update(buf.subarray(0, n));
            pos += n;
        }
    } finally {
        fs.closeSync(fd);
    }
    return hash.digest('hex');
}

/** VA of an ASCII needle inside one section, or null when absent. */
export function findStringVa(fd: number, layout: PeLayout, sectionName: string, needle: string): number | null {
    const sec = section(layout, sectionName);
    if (!sec) return null;
    const needleBuf = Buffer.from(needle, 'latin1');
    const end = sec.rawPtr + sec.rawSize;
    for (let pos = sec.rawPtr; pos < end; pos += CHUNK) {
        const len = Math.min(CHUNK + needleBuf.length, end - pos);
        const at = readAt(fd, pos, len).indexOf(needleBuf);
        if (at >= 0) return fileOffsetToVa(pos + at, layout);
    }
    return null;
}

/** File offsets of `lea reg, [rip+disp]` instructions that point at `targetVa`. */
export function findRipRefsTo(fd: number, layout: PeLayout, targetVa: number): number[] {
    const sec = section(layout, '.text');
    if (!sec) return [];

    const prefixes: Buffer[] = [];
    for (const rex of [0x48, 0x4c]) {
        for (const modrm of [0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d]) {
            prefixes.push(Buffer.from([rex, 0x8d, modrm]));
        }
    }

    const found = new Set<number>();
    const end = sec.rawPtr + sec.rawSize;
    const chunk = Buffer.allocUnsafe(Math.min(CHUNK + OVERLAP, end - sec.rawPtr));
    for (let pos = sec.rawPtr; pos < end; pos += CHUNK) {
        const len = fs.readSync(fd, chunk, 0, Math.min(chunk.length, end - pos), pos);
        if (!len) break;
        for (const prefix of prefixes) {
            let i = chunk.indexOf(prefix);
            while (i >= 0 && i + 7 <= len) {
                const insnVa = layout.imageBase + sec.va + (pos - sec.rawPtr) + i;
                if (insnVa + 7 + chunk.readInt32LE(i + 3) === targetVa) found.add(pos + i);
                i = chunk.indexOf(prefix, i + 1);
            }
        }
    }
    return [...found].sort((a, b) => a - b);
}
