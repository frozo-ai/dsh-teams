// OIDC Authorization Code + PKCE client. Zero dependencies.
// Security-critical: an ID token is only trusted after its RS256 signature
// verifies against the issuer's JWKS AND iss/aud/exp/nonce all match.
import { createHash, randomBytes, createPublicKey, verify as cryptoVerify, timingSafeEqual } from 'node:crypto'

const b64url = (buf) => Buffer.from(buf).toString('base64url')
const CLOCK_SKEW_S = 60

/** PKCE pair: verifier stays server-side, challenge goes to the IdP. */
export function pkce() {
  const verifier = b64url(randomBytes(32))
  const challenge = b64url(createHash('sha256').update(verifier).digest())
  return { verifier, challenge }
}

/** Decode a JWS without verifying — for reading `kid` only. Never trust output. */
export function decodeJwt(token) {
  const parts = String(token).split('.')
  if (parts.length !== 3) throw new Error('malformed JWT')
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'))
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
  return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: parts[2] }
}

const ALGS = { RS256: 'RSA-SHA256', RS384: 'RSA-SHA384', RS512: 'RSA-SHA512' }

/** Verify a JWS against one JWK. Returns true only on a valid signature. */
export function verifySignature(token, jwk) {
  const { header, signingInput, signature } = decodeJwt(token)
  const nodeAlg = ALGS[header.alg]
  if (!nodeAlg) throw new Error(`unsupported alg: ${header.alg}`)
  const key = createPublicKey({ key: jwk, format: 'jwk' })
  return cryptoVerify(nodeAlg, Buffer.from(signingInput), key, Buffer.from(signature, 'base64url'))
}

/**
 * Full ID-token validation. Throws on any failure — callers must not catch
 * and continue.
 * @returns the verified claims.
 */
export function verifyIdToken(token, { jwks, issuer, clientId, nonce, now = Date.now() }) {
  const { header, payload } = decodeJwt(token)
  const jwk = jwks.keys.find((k) => k.kid === header.kid) ?? (jwks.keys.length === 1 ? jwks.keys[0] : undefined)
  if (!jwk) throw new Error(`no JWKS key for kid ${header.kid}`)
  if (!verifySignature(token, jwk)) throw new Error('ID token signature invalid')

  if (payload.iss !== issuer) throw new Error(`issuer mismatch: ${payload.iss}`)
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud]
  if (!aud.includes(clientId)) throw new Error('audience mismatch')
  const nowS = Math.floor(now / 1000)
  if (typeof payload.exp !== 'number' || payload.exp + CLOCK_SKEW_S < nowS) throw new Error('ID token expired')
  if (typeof payload.iat === 'number' && payload.iat - CLOCK_SKEW_S > nowS) throw new Error('ID token issued in the future')
  if (nonce !== undefined) {
    const a = Buffer.from(String(payload.nonce ?? '')), b = Buffer.from(String(nonce))
    if (a.length !== b.length || !timingSafeEqual(a, b)) throw new Error('nonce mismatch (replay?)')
  }
  return payload
}

/** Discover endpoints from the issuer. Cached by the caller. */
export async function discover(issuer) {
  const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`
  const res = await fetch(url)
  if (!res.ok) throw new Error(`OIDC discovery failed (${res.status}) at ${url}`)
  const doc = await res.json()
  for (const f of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'issuer']) {
    if (!doc[f]) throw new Error(`discovery document missing ${f}`)
  }
  return doc
}

export async function fetchJwks(jwksUri) {
  const res = await fetch(jwksUri)
  if (!res.ok) throw new Error(`JWKS fetch failed (${res.status})`)
  const jwks = await res.json()
  if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) throw new Error('JWKS has no keys')
  return jwks
}

/** Build the authorization URL the browser is redirected to. */
export function authorizeUrl(doc, { clientId, redirectUri, state, nonce, challenge, scope = 'openid email profile' }) {
  const u = new URL(doc.authorization_endpoint)
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('client_id', clientId)
  u.searchParams.set('redirect_uri', redirectUri)
  u.searchParams.set('scope', scope)
  u.searchParams.set('state', state)
  u.searchParams.set('nonce', nonce)
  u.searchParams.set('code_challenge', challenge)
  u.searchParams.set('code_challenge_method', 'S256')
  return u.toString()
}

/** Exchange the authorization code for tokens. */
export async function exchangeCode(doc, { code, clientId, clientSecret, redirectUri, verifier }) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code', code, client_id: clientId,
    redirect_uri: redirectUri, code_verifier: verifier,
  })
  const headers = { 'content-type': 'application/x-www-form-urlencoded' }
  // Confidential clients authenticate; public clients rely on PKCE alone.
  if (clientSecret) headers.authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`
  const res = await fetch(doc.token_endpoint, { method: 'POST', headers, body })
  if (!res.ok) throw new Error(`token exchange failed (${res.status}): ${(await res.text()).slice(0, 200)}`)
  const tokens = await res.json()
  if (!tokens.id_token) throw new Error('token response has no id_token')
  return tokens
}

/**
 * Decide whether a verified identity may sign in.
 * `allowedDomains` / `allowedEmails` are the enterprise access control:
 * without one of them ANY account at the IdP could log in.
 */
export function authorizeIdentity(claims, { allowedDomains = [], allowedEmails = [], requireVerifiedEmail = true }) {
  const email = String(claims.email ?? '').toLowerCase()
  if (!email) return { ok: false, reason: 'no email claim' }
  if (requireVerifiedEmail && claims.email_verified === false) return { ok: false, reason: 'email not verified' }
  if (allowedEmails.length && allowedEmails.map((e) => e.toLowerCase()).includes(email)) return { ok: true, email }
  if (allowedDomains.length) {
    const domain = email.split('@')[1] ?? ''
    if (allowedDomains.map((d) => d.toLowerCase().replace(/^@/, '')).includes(domain)) return { ok: true, email }
  }
  if (!allowedDomains.length && !allowedEmails.length) {
    return { ok: false, reason: 'no allowlist configured — refusing to admit every account at the IdP' }
  }
  return { ok: false, reason: `${email} is not in the allowlist` }
}
