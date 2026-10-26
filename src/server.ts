/**
 * In-process stand-in for the CloakBrowser license API.
 *
 * The Pro binary reads the API base URL from CLOAKBROWSER_LICENSE_API and talks
 * plain JSON over HTTP to these paths:
 *
 *   POST /api/license/session/start      acquire a lease (this is the seat check)
 *   POST /api/license/session/heartbeat  keep it alive
 *   POST /api/license/session/end        release it
 *   POST /api/license/validate           wrapper-side key validation
 *   GET  /api/download/version           Pro release resolution
 *
 * We answer every request with a fresh, well-formed "business" lease. The token
 * signature is random because the patched binary never verifies it.
 */
import http from 'node:http';
import crypto from 'node:crypto';
import type {
    LicenseGrant, LicenseRequestBody, LicenseServer, LicenseServerOptions, LicenseServerStats,
} from './types.js';

const b64u = (buf: Buffer): string =>
    Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_');
const sha256hex = (value: string): string =>
    crypto.createHash('sha256').update(value).digest('hex');

export function createLicenseServer(options: LicenseServerOptions = {}): Promise<LicenseServer> {
    const { plan = 'business', host = '127.0.0.1', port = 0, log = () => {} } = options;

    const stats: LicenseServerStats = {
        starts: 0, heartbeats: 0, ends: 0, validates: 0, leases: new Set<string>(),
    };

    const issue = (req: LicenseRequestBody): LicenseGrant => {
        const now = Date.now();
        const leaseId = `lease_${crypto.randomBytes(16).toString('hex')}`;
        stats.leases.add(leaseId);
        const payload = {
            K_wrapped: crypto.randomBytes(92).toString('hex'),
            expires_at: new Date(now + 24 * 3600_000).toISOString(),
            install_id: req.install_id,
            instance_id: req.instance_id,
            issued_at: new Date(now).toISOString(),
            lease_id: leaseId,
            license_key_hash: sha256hex(req.license_key ?? ''),
            plan,
            platform: req.platform ?? 'windows-x64',
            version: req.version ?? '',
        };
        const token = `${b64u(Buffer.from(JSON.stringify(payload)))}.${b64u(crypto.randomBytes(64))}`;
        return {
            valid: true,
            lease_id: leaseId,
            heartbeat_interval_seconds: 60,
            lease_ttl_seconds: 24 * 3600,
            plan,
            token,
        };
    };

    const server = http.createServer((req, res) => {
        let body = '';
        req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        req.on('end', () => {
            let parsed: LicenseRequestBody = {};
            try { parsed = body ? (JSON.parse(body) as LicenseRequestBody) : {}; } catch { /* ignore */ }
            const route = (req.url ?? '').split('?')[0];
            const send = (obj: unknown, code = 200): void => {
                const out = JSON.stringify(obj);
                res.writeHead(code, {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(out),
                });
                res.end(out);
            };

            switch (route) {
                case '/api/license/session/start': {
                    const grant = issue(parsed);
                    stats.starts++;
                    log(`grant ${grant.lease_id} instance=${parsed.instance_id ?? '-'}`);
                    return send(grant);
                }
                case '/api/license/session/heartbeat': {
                    const grant = issue(parsed);
                    stats.heartbeats++;
                    log(`heartbeat ${grant.lease_id}`);
                    return send(grant);
                }
                case '/api/license/session/end':
                    stats.ends++;
                    if (parsed.lease_id) stats.leases.delete(parsed.lease_id);
                    log('release');
                    return send({ valid: true });
                case '/api/license/validate':
                    stats.validates++;
                    log('validate');
                    return send({ valid: true, plan, expires: null });
                case '/api/download/version':
                    return send({
                        version: parsed.version || '154.0.8037.57.1',
                        requested_channel: 'stable',
                        resolved_channel: 'stable',
                        fallback: false,
                    });
                default:
                    log(`404 ${route}`);
                    return send({ error: 'not_found' }, 404);
            }
        });
    });

    return new Promise<LicenseServer>((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
            const address = server.address();
            if (address == null || typeof address === 'string') {
                return reject(new Error('license api failed to bind a TCP port'));
            }
            const url = `http://${host}:${address.port}`;
            log(`license api listening on ${url} plan=${plan}`);
            resolve({
                server,
                url,
                port: address.port,
                stats,
                close: () => new Promise<void>((done, fail) =>
                    server.close(err => (err ? fail(err) : done()))),
            });
        });
    });
}
