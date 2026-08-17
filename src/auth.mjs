// dsh-teams auth core: users store (scrypt), cookie sessions, login rate limit.
// Zero dependencies — node:crypto + node:fs only.
import { scryptSync, randomBytes, timingSafeEqual, createHmac } from 'node:crypto'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'

const SCRYPT_N = 16384
const SESSION_TTL_MS = 12 * 60 * 60 * 1000 // 12h
const LOGIN_WINDOW_MS = 15 * 60 * 1000
const LOGIN_MAX_ATTEMPTS = 10

export function hashPassword(password) {
  const salt = randomBytes(16)
  const hash = scryptSync(password, salt, 32, { N: SCRYPT_N })
  return `scrypt:${salt.toString('hex')}:${hash.toString('hex')}`
}

export function verifyPassword(password, stored) {
  const [scheme, saltHex, hashHex] = String(stored).split(':')
  if (scheme !== 'scrypt' || !saltHex || !hashHex) return false
  const expected = Buffer.from(hashHex, 'hex')
  const actual = scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length, { N: SCRYPT_N })
  return actual.length === expected.length && timingSafeEqual(actual, expected)
}

export class UserStore {
  constructor(path) {
    this.path = path
  }
  load() {
    if (!existsSync(this.path)) return {}
    return JSON.parse(readFileSync(this.path, 'utf8'))
  }
  save(users) {
    writeFileSync(this.path, JSON.stringify(users, null, 2) + '\n', { mode: 0o600 })
  }
  addUser(name, password) {
    if (!/^[a-z0-9_.-]{1,64}$/i.test(name)) throw new Error('invalid username (a-z 0-9 _ . - only)')
    const users = this.load()
    users[name] = { password: hashPassword(password), createdAt: new Date().toISOString() }
    this.save(users)
  }
  removeUser(name) {
    const users = this.load()
    if (!(name in users)) return false
    delete users[name]
    this.save(users)
    return true
  }
  verify(name, password) {
    const user = this.load()[name]
    if (!user) {
      // Burn comparable time so absent users are not distinguishable by latency.
      verifyPassword(password, 'scrypt:00:00')
      return false
    }
    return verifyPassword(password, user.password)
  }
  list() {
    return Object.keys(this.load())
  }
}

export class SessionStore {
  constructor(secret) {
    this.secret = secret
    this.sessions = new Map() // token -> { user, expiresAt }
  }
  sign(token) {
    return createHmac('sha256', this.secret).update(token).digest('hex').slice(0, 32)
  }
  create(user) {
    const token = randomBytes(24).toString('hex')
    this.sessions.set(token, { user, expiresAt: Date.now() + SESSION_TTL_MS })
    return `${token}.${this.sign(token)}`
  }
  resolve(cookieValue) {
    if (!cookieValue) return null
    const [token, sig] = String(cookieValue).split('.')
    if (!token || !sig) return null
    const expected = this.sign(token)
    const a = Buffer.from(sig)
    const b = Buffer.from(expected)
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null
    const session = this.sessions.get(token)
    if (!session) return null
    if (session.expiresAt < Date.now()) {
      this.sessions.delete(token)
      return null
    }
    return session.user
  }
  destroy(cookieValue) {
    const token = String(cookieValue ?? '').split('.')[0]
    if (token) this.sessions.delete(token)
  }
}

export class LoginRateLimit {
  constructor() {
    this.attempts = new Map() // ip -> { count, windowStart }
  }
  allow(ip) {
    const now = Date.now()
    const entry = this.attempts.get(ip)
    if (!entry || now - entry.windowStart > LOGIN_WINDOW_MS) {
      this.attempts.set(ip, { count: 1, windowStart: now })
      return true
    }
    entry.count += 1
    return entry.count <= LOGIN_MAX_ATTEMPTS
  }
}

export function parseCookies(header) {
  const cookies = {}
  for (const part of String(header ?? '').split(';')) {
    const idx = part.indexOf('=')
    if (idx > 0) cookies[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim())
  }
  return cookies
}
