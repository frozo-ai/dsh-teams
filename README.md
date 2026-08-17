# dsh-teams

**Team access for the [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) web UI.**

The dsh web server ships with [no TLS, auth, or origin policy — deliberately out of scope](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/host/webserver/README.md#known-limitations-and-deferred-work). That's correct for a loopback dev tool, and a problem the moment you want your team on one shared instance.

`dsh-teams` is a zero-dependency auth gateway: a login wall plus a full HTTP **and WebSocket** reverse proxy in front of a loopback-bound `dsh web`. Your dsh stays on `127.0.0.1`; the gateway is the only thing exposed.

```
browser ──> dsh-teams :3081 (auth wall) ──> dsh web 127.0.0.1:3080
```

## Quick start

```sh
# 1. run dsh as usual (loopback-bound, the default)
npx @deepseek-ai/dsh web

# 2. create a user and start the gateway
npx dsh-teams add-user alice
npx dsh-teams start          # http://0.0.0.0:3081 -> 127.0.0.1:3080
```

Point your team at `http://<host>:3081`. Unauthenticated requests — including WebSocket upgrades — get a login page; authenticated ones are proxied through untouched.

## What it does

- **Login wall** on every HTTP route and WebSocket upgrade
- **scrypt** password hashing, HMAC-signed HttpOnly cookies, login rate limiting (10 tries / 15 min / IP)
- Forwards the authenticated username upstream as `x-dsh-teams-user` (audit / future per-user routing)
- **Zero npm dependencies** — `node:http`, `node:net`, `node:crypto`; survives dsh rc churn because it never touches dsh internals

## CLI

```
dsh-teams add-user <name> [password]   create user (prompts if password omitted)
dsh-teams start [port]                 start gateway (default 3081)
dsh-teams remove-user <name>
dsh-teams list-users
```

Env: `DSH_TEAMS_PORT`, `DSH_TEAMS_HOST`, `DSH_UPSTREAM_HOST`, `DSH_UPSTREAM_PORT`, `DSH_TEAMS_HOME` (default `~/.dsh-teams`).

## Security notes

- Run behind TLS (Caddy/nginx/Cloudflare Tunnel) for anything beyond a trusted LAN — cookies are not `Secure` over plain HTTP.
- All authenticated users share one dsh instance and see the same sessions/workspaces. Per-user isolated instances are the next milestone (below).
- Sessions are in-memory: restarting the gateway logs everyone out.

## Roadmap

- [ ] **Per-user dsh instances** — one process + `DSH_HOME` per user, gateway routes by identity (true isolation)
- [ ] OIDC / SSO login (Google, GitHub, Okta)
- [ ] Roles & per-user workspace allowlists
- [ ] Usage quotas per user
- [ ] Audit log of who ran what

## Test

```sh
npm test   # 6-check smoke test: wall, bad login, login, proxy, tamper, logout
```

MIT. Not affiliated with DeepSeek AI.
