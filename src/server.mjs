// dsh-teams gateway: cookie-auth wall + full HTTP/WebSocket reverse proxy in
// front of a loopback-bound DeepSeek Harness web UI. Zero dependencies.
import { createServer, request as httpRequest } from 'node:http'
import { connect } from 'node:net'
import { UserStore, SessionStore, LoginRateLimit, parseCookies } from './auth.mjs'

const COOKIE_NAME = 'dsh_teams_session'
// Hop-by-hop headers must not be forwarded (RFC 9110 §7.6.1).
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
])

const LOGIN_PAGE = (error) => `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>dsh-teams login</title>
<style>
  body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#0d1117;color:#e6edf3}
  form{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:2rem;width:min(90vw,20rem)}
  h1{font-size:1.1rem;margin:0 0 1rem}
  input{display:block;width:100%;box-sizing:border-box;margin:.5rem 0;padding:.5rem;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:inherit}
  button{width:100%;padding:.5rem;margin-top:.5rem;border-radius:6px;border:0;background:#238636;color:#fff;font-weight:600;cursor:pointer}
  .err{color:#f85149;font-size:.85rem;min-height:1.2em}
</style></head>
<body><form method="post" action="/__teams/login">
<h1>DeepSeek Harness — sign in</h1>
<div class="err">${error ?? ''}</div>
<input name="user" placeholder="username" autocomplete="username" required>
<input name="password" type="password" placeholder="password" autocomplete="current-password" required>
<button>Sign in</button>
</form></body></html>`

export function startGateway(config) {
  const { port, host, upstreamHost, upstreamPort, usersPath, secret } = config
  const users = new UserStore(usersPath)
  const sessions = new SessionStore(secret)
  const rateLimit = new LoginRateLimit()

  const authedUser = (req) => sessions.resolve(parseCookies(req.headers.cookie)[COOKIE_NAME])

  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://gateway')

    if (url.pathname === '/__teams/login' && req.method === 'POST') {
      return handleLogin(req, res)
    }
    if (url.pathname === '/__teams/logout') {
      sessions.destroy(parseCookies(req.headers.cookie)[COOKIE_NAME])
      res.writeHead(302, { 'set-cookie': `${COOKIE_NAME}=; Max-Age=0; Path=/`, location: '/' })
      return res.end()
    }

    const user = authedUser(req)
    if (!user) {
      res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' })
      return res.end(LOGIN_PAGE())
    }
    proxyHttp(req, res, user)
  })

  server.on('upgrade', (req, socket) => {
    const user = authedUser(req)
    if (!user) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
      return socket.destroy()
    }
    proxyUpgrade(req, socket)
  })

  function handleLogin(req, res) {
    const ip = req.socket.remoteAddress ?? 'unknown'
    if (!rateLimit.allow(ip)) {
      res.writeHead(429, { 'content-type': 'text/html; charset=utf-8' })
      return res.end(LOGIN_PAGE('Too many attempts — try again in 15 minutes.'))
    }
    let body = ''
    req.on('data', (chunk) => {
      body += chunk
      if (body.length > 4096) req.destroy()
    })
    req.on('end', () => {
      const form = new URLSearchParams(body)
      const name = form.get('user') ?? ''
      if (users.verify(name, form.get('password') ?? '')) {
        const cookie = sessions.create(name)
        res.writeHead(302, {
          'set-cookie': `${COOKIE_NAME}=${cookie}; HttpOnly; SameSite=Lax; Path=/`,
          location: '/',
        })
        return res.end()
      }
      res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' })
      res.end(LOGIN_PAGE('Invalid username or password.'))
    })
  }

  function upstreamHeaders(req, user) {
    const headers = {}
    for (const [key, value] of Object.entries(req.headers)) {
      if (!HOP_BY_HOP.has(key)) headers[key] = value
    }
    headers['x-dsh-teams-user'] = user // ready for future per-user routing/audit
    return headers
  }

  function proxyHttp(req, res, user) {
    const upstream = httpRequest({
      host: upstreamHost,
      port: upstreamPort,
      method: req.method,
      path: req.url,
      headers: upstreamHeaders(req, user),
    }, (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers)
      upstreamRes.pipe(res)
    })
    upstream.on('error', () => {
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' })
      res.end('dsh upstream unreachable')
    })
    req.pipe(upstream)
  }

  function proxyUpgrade(req, socket) {
    const upstream = connect(upstreamPort, upstreamHost, () => {
      let head = `${req.method} ${req.url} HTTP/1.1\r\n`
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        head += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`
      }
      upstream.write(head + '\r\n')
      socket.pipe(upstream)
      upstream.pipe(socket)
    })
    const drop = () => {
      socket.destroy()
      upstream.destroy()
    }
    upstream.on('error', drop)
    socket.on('error', drop)
  }

  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, host, () => resolve(server))
  })
}
