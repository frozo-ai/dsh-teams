#!/usr/bin/env node
// dsh-teams CLI: start | add-user | remove-user | list-users
import { randomBytes } from 'node:crypto'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline/promises'
import { UserStore } from '../src/auth.mjs'
import { startGateway } from '../src/server.mjs'

const HOME = process.env.DSH_TEAMS_HOME ?? join(homedir(), '.dsh-teams')
mkdirSync(HOME, { recursive: true })
const USERS_PATH = join(HOME, 'users.json')
const SECRET_PATH = join(HOME, '.secret')

function loadSecret() {
  if (!existsSync(SECRET_PATH)) {
    writeFileSync(SECRET_PATH, randomBytes(32).toString('hex'), { mode: 0o600 })
  }
  return readFileSync(SECRET_PATH, 'utf8').trim()
}

async function promptPassword(label) {
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  const value = await rl.question(`${label}: `)
  rl.close()
  return value
}

const [command, ...args] = process.argv.slice(2)
const users = new UserStore(USERS_PATH)

switch (command) {
  case 'start': {
    const port = Number(process.env.DSH_TEAMS_PORT ?? args[0] ?? 3081)
    const host = process.env.DSH_TEAMS_HOST ?? '0.0.0.0'
    const upstreamPort = Number(process.env.DSH_UPSTREAM_PORT ?? 3080)
    const upstreamHost = process.env.DSH_UPSTREAM_HOST ?? '127.0.0.1'
    if (users.list().length === 0) {
      console.error('No users yet. Create one first: dsh-teams add-user <name>')
      process.exit(1)
    }
    await startGateway({ port, host, upstreamHost, upstreamPort, usersPath: USERS_PATH, secret: loadSecret() })
    console.log(`dsh-teams gateway on http://${host}:${port} -> dsh at ${upstreamHost}:${upstreamPort}`)
    console.log(`users: ${users.list().join(', ')}  (store: ${USERS_PATH})`)
    break
  }
  case 'add-user': {
    const name = args[0]
    if (!name) {
      console.error('usage: dsh-teams add-user <name>')
      process.exit(1)
    }
    const password = args[1] ?? await promptPassword(`password for ${name}`)
    if (password.length < 8) {
      console.error('password must be at least 8 characters')
      process.exit(1)
    }
    users.addUser(name, password)
    console.log(`added user ${name}`)
    break
  }
  case 'remove-user': {
    const removed = users.removeUser(args[0] ?? '')
    console.log(removed ? `removed ${args[0]}` : 'no such user')
    break
  }
  case 'list-users': {
    console.log(users.list().join('\n') || '(no users)')
    break
  }
  default:
    console.log(`dsh-teams — auth gateway for the DeepSeek Harness web UI

usage:
  dsh-teams add-user <name> [password]   create a user (interactive prompt if omitted)
  dsh-teams start [port]                 start gateway (default 3081 -> 127.0.0.1:3080)
  dsh-teams remove-user <name>
  dsh-teams list-users

env: DSH_TEAMS_PORT, DSH_TEAMS_HOST, DSH_UPSTREAM_HOST, DSH_UPSTREAM_PORT, DSH_TEAMS_HOME`)
}
