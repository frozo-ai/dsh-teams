// SSO tests against a FAKE-BUT-REAL OIDC provider: a genuine RSA keypair
// signing genuine RS256 tokens. The crypto path is exercised for real.
// Run: node test/oidc.test.mjs
import assert from 'node:assert'
import { createServer } from 'node:http'
import { generateKeyPairSync, createSign, randomBytes } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { UserStore } from '../src/auth.mjs'
import { startGateway } from '../src/server.mjs'
import { verifyIdToken, authorizeIdentity, pkce, decodeJwt } from '../src/oidc.mjs'

let n = 0
const ok = (m) => { n++; console.log(`  ok  ${m}`) }
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'test-key-1', alg: 'RS256', use: 'sig' }
const JWKS = { keys: [jwk] }
const CLIENT_ID = 'dsh-teams-test'

function signToken(payload, { kid = 'test-key-1', key = privateKey } = {}) {
  const header = b64({ alg: 'RS256', typ: 'JWT', kid })
  const body = b64(payload)
  const s = createSign('RSA-SHA256'); s.update(`${header}.${body}`); s.end()
  return `${header}.${body}.${s.sign(key).toString('base64url')}`
}
const baseClaims = (over = {}) => ({
  iss: ISSUER, aud: CLIENT_ID, sub: 'user-1', email: 'alice@corp.example',
  email_verified: true, exp: Math.floor(Date.now()/1000) + 300, iat: Math.floor(Date.now()/1000),
  nonce: 'test-nonce', ...over,
})

// ---- fake IdP ----
let ISSUER, lastAuthQuery
const idp = createServer((req, res) => {
  const u = new URL(req.url, ISSUER)
  const json = (o) => { res.writeHead(200, {'content-type':'application/json'}); res.end(JSON.stringify(o)) }
  if (u.pathname === '/.well-known/openid-configuration') return json({
    issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`, jwks_uri: `${ISSUER}/jwks`,
  })
  if (u.pathname === '/jwks') return json(JWKS)
  if (u.pathname === '/authorize') { lastAuthQuery = u.searchParams; res.writeHead(200); return res.end('idp-login-page') }
  if (u.pathname === '/token') {
    let body = ''
    req.on('data', (c) => body += c)
    return req.on('end', () => {
      const p = new URLSearchParams(body)
      // PKCE must be present -- the whole point of the flow
      if (!p.get('code_verifier')) { res.writeHead(400); return res.end('missing code_verifier') }
      json({ id_token: signToken(baseClaims({ nonce: TOKEN_NONCE })), token_type: 'Bearer' })
    })
  }
  res.writeHead(404); res.end()
})
await new Promise((r) => idp.listen(0, '127.0.0.1', r))
ISSUER = `http://127.0.0.1:${idp.address().port}`
let TOKEN_NONCE = 'test-nonce'

// ================= unit: token verification =================
const good = signToken(baseClaims())
const v = verifyIdToken(good, { jwks: JWKS, issuer: ISSUER, clientId: CLIENT_ID, nonce: 'test-nonce' })
assert.equal(v.email, 'alice@corp.example'); ok('valid RS256 ID token accepted')

const reject = (token, opts, label) => {
  assert.throws(() => verifyIdToken(token, { jwks: JWKS, issuer: ISSUER, clientId: CLIENT_ID, nonce: 'test-nonce', ...opts }))
  ok(`rejected: ${label}`)
}
// tamper the payload, keep the old signature
const parts = good.split('.')
const forged = `${parts[0]}.${b64(baseClaims({ email: 'attacker@evil.example' }))}.${parts[2]}`
reject(forged, {}, 'tampered payload (signature mismatch)')

const { privateKey: otherKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
reject(signToken(baseClaims(), { key: otherKey }), {}, 'token signed by the wrong key')
reject(signToken(baseClaims({ iss: 'https://evil.example' })), {}, 'issuer mismatch')
reject(signToken(baseClaims({ aud: 'some-other-client' })), {}, 'audience mismatch')
reject(signToken(baseClaims({ exp: Math.floor(Date.now()/1000) - 3600 })), {}, 'expired token')
reject(signToken(baseClaims({ nonce: 'different-nonce' })), {}, 'nonce mismatch (replay)')

// alg:none must never be accepted
const noneTok = `${b64({alg:'none',typ:'JWT',kid:'test-key-1'})}.${b64(baseClaims())}.`
assert.throws(() => verifyIdToken(noneTok, { jwks: JWKS, issuer: ISSUER, clientId: CLIENT_ID }))
ok('rejected: alg=none downgrade attack')

// ================= unit: access control =================
assert.equal(authorizeIdentity({ email: 'a@corp.example', email_verified: true }, { allowedDomains: ['corp.example'] }).ok, true)
ok('allowlisted domain admitted')
assert.equal(authorizeIdentity({ email: 'a@evil.example', email_verified: true }, { allowedDomains: ['corp.example'] }).ok, false)
ok('non-allowlisted domain refused')
assert.equal(authorizeIdentity({ email: 'a@corp.example', email_verified: false }, { allowedDomains: ['corp.example'] }).ok, false)
ok('unverified email refused')
const noList = authorizeIdentity({ email: 'anyone@gmail.com', email_verified: true }, {})
assert.equal(noList.ok, false)
assert.match(noList.reason, /no allowlist/)
ok('fails CLOSED with no allowlist (will not admit every IdP account)')

// ================= integration: full flow through the gateway =================
const home = mkdtempSync(join(tmpdir(), 'dsh-sso-'))
const usersPath = join(home, 'users.json')
new UserStore(usersPath).addUser('local', 'password123')
const upstream = createServer((req, res) => { res.writeHead(200); res.end(`hello ${req.headers['x-dsh-teams-user']}`) })
await new Promise((r) => upstream.listen(0, '127.0.0.1', r))

const gw = await startGateway({
  port: 0, host: '127.0.0.1', upstreamHost: '127.0.0.1', upstreamPort: upstream.address().port,
  usersPath, secret: 'test-secret',
  oidc: { issuer: ISSUER, clientId: CLIENT_ID, redirectUri: 'http://127.0.0.1/cb',
          allowedDomains: ['corp.example'], label: 'TestIdP' },
})
const base = `http://127.0.0.1:${gw.address().port}`

let res = await fetch(base + '/')
assert.match(await res.text(), /Sign in with TestIdP/); ok('login page shows the SSO button when configured')

res = await fetch(base + '/__teams/sso/login', { redirect: 'manual' })
assert.equal(res.status, 302)
const loc = new URL(res.headers.get('location'))
assert.equal(loc.searchParams.get('code_challenge_method'), 'S256'); ok('authorize redirect uses PKCE S256')
assert.ok(loc.searchParams.get('state')); ok('authorize redirect carries state')
assert.ok(loc.searchParams.get('nonce')); ok('authorize redirect carries nonce')
const state = loc.searchParams.get('state')
TOKEN_NONCE = loc.searchParams.get('nonce')

// forged/unknown state must be refused
res = await fetch(`${base}/__teams/sso/callback?code=x&state=forged-state`)
assert.equal(res.status, 400); ok('callback rejects unknown state (CSRF)')

res = await fetch(`${base}/__teams/sso/callback?code=valid-code&state=${state}`, { redirect: 'manual' })
assert.equal(res.status, 302, 'valid callback should sign the user in')
const cookie = res.headers.get('set-cookie').split(';')[0]
ok('valid SSO callback issues a session cookie')

res = await fetch(base + '/whoami', { headers: { cookie } })
assert.equal(await res.text(), 'hello alice@corp.example')
ok('SSO session proxies upstream with the verified email as identity')

// state is single-use
res = await fetch(`${base}/__teams/sso/callback?code=valid-code&state=${state}`)
assert.equal(res.status, 400); ok('state is single-use (replay refused)')

// password login still works alongside SSO
res = await fetch(base + '/__teams/login', { method: 'POST', redirect: 'manual',
  headers: {'content-type':'application/x-www-form-urlencoded'}, body: 'user=local&password=password123' })
assert.equal(res.status, 302); ok('password auth still works alongside SSO')

gw.close(); upstream.close(); idp.close()
console.log(`\n${n} checks passed (SSO / OIDC)`)
