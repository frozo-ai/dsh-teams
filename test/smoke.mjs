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

// Dummy upstream standing in for the dsh web UI.
const upstream = createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' })
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
