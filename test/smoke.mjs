// Smoke test: login wall blocks, login works, proxy forwards, logout revokes.
// Run: node test/smoke.mjs
import assert from 'node:assert'
import { createServer } from 'node:http'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { UserStore } from '../src/auth.mjs'
import { startGateway } from '../src/server.mjs'

const home = mkdtempSync(join(tmpdir(), 'dsh-teams-test-'))
const usersPath = join(home, 'users.json')
new UserStore(usersPath).addUser('alice', 'password123')

// Dummy upstream standing in for the dsh web UI. /asset streams a large
// CHUNKED body with the same hop-by-hop headers real dsh sends, so the
// proxy's response-header stripping is actually exercised.
const BIG_ASSET = 'x'.repeat(200_000)
const upstream = createServer((req, res) => {
  if (req.url === '/asset') {
    res.writeHead(200, {
      'content-type': 'text/css',
      connection: 'keep-alive',
      'keep-alive': 'timeout=5',
      // no content-length -> node uses Transfer-Encoding: chunked, exactly
      // like the real dsh web server does
    })
    for (let i = 0; i < BIG_ASSET.length; i += 16_384) res.write(BIG_ASSET.slice(i, i + 16_384))
    return res.end()
  }
  if (req.url === '/api/probe') {
    // Mimic dsh: reject anything carrying an Origin header (loopback-only CSRF
    // assumption). The proxy must strip it or the whole API 403s behind a proxy.
    if (req.headers.origin) { res.writeHead(403); return res.end('forbidden') }
    res.writeHead(200, { 'content-type': 'application/json' })
    return res.end(JSON.stringify({ ok: true, host: req.headers.host, fwd: req.headers['x-forwarded-host'] }))
  }
  res.writeHead(200, { 'content-type': 'text/plain', connection: 'keep-alive' })
  res.end(`upstream saw ${req.url} for ${req.headers['x-dsh-teams-user']}`)
})
await new Promise((r) => upstream.listen(0, '127.0.0.1', r))

const gateway = await startGateway({
  port: 0,
  host: '127.0.0.1',
  upstreamHost: '127.0.0.1',
  upstreamPort: upstream.address().port,
  usersPath,
  secret: 'test-secret',
})
const base = `http://127.0.0.1:${gateway.address().port}`

// 1. Unauthenticated -> 401 login page
let res = await fetch(base + '/')
assert.equal(res.status, 401)
assert.match(await res.text(), /sign in/i)

// 2. Wrong password -> 401
res = await fetch(base + '/__teams/login', {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: 'user=alice&password=wrong',
})
assert.equal(res.status, 401)

// 3. Correct login -> 302 + session cookie
res = await fetch(base + '/__teams/login', {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: 'user=alice&password=password123',
  redirect: 'manual',
})
assert.equal(res.status, 302)
const cookie = res.headers.get('set-cookie').split(';')[0]
assert.ok(cookie.startsWith('dsh_teams_session='))

// 4. Authenticated -> proxied, user identity forwarded
res = await fetch(base + '/some/path', { headers: { cookie } })
assert.equal(res.status, 200)
assert.equal(await res.text(), 'upstream saw /some/path for alice')

// 4b. REGRESSION: a large chunked asset must arrive byte-identical.
// Forwarding upstream's own Transfer-Encoding while node applies its framing
// double-encodes the body and truncates CSS/JS -- that broke the real UI
// through the gateway while direct access worked fine.
res = await fetch(base + '/asset', { headers: { cookie } })
const asset = await res.text()
assert.equal(res.status, 200)
assert.equal(asset.length, 200_000, `chunked asset truncated: got ${asset.length} of 200000 bytes`)
assert.ok(/^x+$/.test(asset), 'chunked asset corrupted')

// 4c. REGRESSION: a browser sends Origin through a proxy; dsh 403s on it.
// The proxy must strip Origin/Referer and rewrite Host so upstream sees the
// loopback client it expects. Without this every /api call fails and the UI
// half-renders while static assets load fine.
res = await fetch(base + '/api/probe', {
  headers: { cookie, origin: 'https://example.ts.net', referer: 'https://example.ts.net/' },
})
assert.equal(res.status, 200, 'Origin must be stripped or upstream 403s')
const api = await res.json()
assert.ok(api.ok)
assert.match(api.host, /^127\.0\.0\.1:/, 'Host must be rewritten to the upstream')
assert.equal(api.fwd, new URL(base).host, 'original host preserved as x-forwarded-host')

// 5. Tampered cookie -> 401
res = await fetch(base + '/', { headers: { cookie: cookie.slice(0, -4) + 'beef' } })
assert.equal(res.status, 401)

// 6. Logout -> session revoked
await fetch(base + '/__teams/logout', { headers: { cookie }, redirect: 'manual' })
res = await fetch(base + '/', { headers: { cookie } })
assert.equal(res.status, 401)

console.log('smoke: all 6 checks passed')
gateway.close()
upstream.close()
