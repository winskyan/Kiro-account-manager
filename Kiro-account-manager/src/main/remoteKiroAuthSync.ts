import { spawn } from 'child_process'
import { readFile } from 'fs/promises'
import * as path from 'path'

export interface RemoteKiroSyncSettings {
  enabled: boolean
  targets: string[]
  connectTimeoutSeconds: number
}

export interface RemoteKiroSyncTargetResult {
  target: string
  success: boolean
  error?: string
}

export interface RemoteKiroSyncResult {
  success: boolean
  skipped?: boolean
  reason?: string
  results: RemoteKiroSyncTargetResult[]
}

export const DEFAULT_REMOTE_KIRO_SYNC_SETTINGS: RemoteKiroSyncSettings = {
  enabled: false,
  targets: [],
  connectTimeoutSeconds: 8
}

const MAX_OUTPUT_BYTES = 8 * 1024
const CLIENT_REGISTRATION_NAME = /^[a-f0-9]{40}\.json$/
const SSH_TARGET = /^(?:[A-Za-z0-9_.:@%+-]|\[|\])+$/

const REMOTE_WRITE_SCRIPT = `set -eu
cache_dir="$HOME/.aws/sso/cache"
mkdir -p "$cache_dir"
umask 077
IFS= read -r token_b64
IFS= read -r registration_name
IFS= read -r registration_b64
decode_base64() {
  if printf '' | base64 --decode >/dev/null 2>&1; then
    base64 --decode
  elif printf '' | base64 -d >/dev/null 2>&1; then
    base64 -d
  elif printf '' | base64 -D >/dev/null 2>&1; then
    base64 -D
  elif command -v openssl >/dev/null 2>&1; then
    openssl base64 -d -A
  else
    echo 'remote host has no supported base64 decoder' >&2
    exit 127
  fi
}
token_tmp="$cache_dir/.kiro-auth-token.json.tmp.$$"
registration_tmp=''
cleanup() {
  rm -f "$token_tmp"
  if [ -n "$registration_tmp" ]; then rm -f "$registration_tmp"; fi
}
trap cleanup EXIT HUP INT TERM
printf '%s' "$token_b64" | decode_base64 > "$token_tmp"
chmod 600 "$token_tmp"
if [ -n "$registration_name" ]; then
  if [ "\${#registration_name}" -ne 45 ]; then
    echo 'invalid client registration filename length' >&2
    exit 2
  fi
  registration_hash="\${registration_name%.json}"
  case "$registration_name" in
    *.json) ;;
    *)
      echo 'invalid client registration filename' >&2
      exit 2
      ;;
  esac
  case "$registration_hash" in
    *[!0-9a-f]*)
      echo 'invalid client registration hash' >&2
      exit 2
      ;;
  esac
  registration_tmp="$cache_dir/.$registration_name.tmp.$$"
  printf '%s' "$registration_b64" | decode_base64 > "$registration_tmp"
  chmod 600 "$registration_tmp"
  mv -f "$registration_tmp" "$cache_dir/$registration_name"
fi
mv -f "$token_tmp" "$cache_dir/kiro-auth-token.json"
trap - EXIT HUP INT TERM
printf 'synced\n'
`

const REMOTE_TEST_SCRIPT = `set -eu
command -v base64 >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1
test -n "$HOME"
printf 'ready\n'
`

function quotePosixShell(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

const REMOTE_WRITE_COMMAND = `sh -c ${quotePosixShell(REMOTE_WRITE_SCRIPT)}`
const REMOTE_TEST_COMMAND = `sh -c ${quotePosixShell(REMOTE_TEST_SCRIPT)}`

export function normalizeRemoteKiroSyncSettings(
  input?: Partial<RemoteKiroSyncSettings> | null
): RemoteKiroSyncSettings {
  const targets = Array.from(
    new Set((input?.targets || []).map((target) => target.trim()).filter(Boolean))
  ).slice(0, 20)
  const rawTimeout = Number(input?.connectTimeoutSeconds)
  const connectTimeoutSeconds = Number.isFinite(rawTimeout)
    ? Math.max(3, Math.min(30, Math.round(rawTimeout)))
    : DEFAULT_REMOTE_KIRO_SYNC_SETTINGS.connectTimeoutSeconds

  return {
    enabled: input?.enabled === true,
    targets,
    connectTimeoutSeconds
  }
}

export function validateRemoteKiroTarget(target: string): string | null {
  if (!target) return 'SSH target is empty'
  if (target.length > 255) return 'SSH target is too long'
  if (target.startsWith('-')) return 'SSH target cannot start with "-"'
  if (!SSH_TARGET.test(target)) {
    return 'SSH target may only contain a host alias, hostname, IP, and optional user@ prefix'
  }
  return null
}

interface RunSshOptions {
  target: string
  connectTimeoutSeconds: number
  command: string
  stdin: string
}

function appendLimited(current: string, chunk: Buffer): string {
  if (current.length >= MAX_OUTPUT_BYTES) return current
  return (current + chunk.toString('utf8')).slice(0, MAX_OUTPUT_BYTES)
}

function runSshScript(options: RunSshOptions): Promise<{ success: boolean; output: string; error?: string }> {
  return new Promise((resolve) => {
    const validationError = validateRemoteKiroTarget(options.target)
    if (validationError) {
      resolve({ success: false, output: '', error: validationError })
      return
    }

    const child = spawn(
      'ssh',
      [
        '-o', 'BatchMode=yes',
        '-o', `ConnectTimeout=${options.connectTimeoutSeconds}`,
        '-o', 'LogLevel=ERROR',
        options.target,
        options.command
      ],
      {
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true
      }
    )

    let stdout = ''
    let stderr = ''
    let settled = false
    const finish = (result: { success: boolean; output: string; error?: string }): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(result)
    }
    const timer = setTimeout(() => {
      child.kill()
      finish({
        success: false,
        output: stdout.trim(),
        error: `SSH connection timed out after ${options.connectTimeoutSeconds}s`
      })
    }, (options.connectTimeoutSeconds + 3) * 1000)

    child.stdout.on('data', (chunk: Buffer) => { stdout = appendLimited(stdout, chunk) })
    child.stderr.on('data', (chunk: Buffer) => { stderr = appendLimited(stderr, chunk) })
    child.on('error', (error) => {
      finish({ success: false, output: stdout.trim(), error: error.message })
    })
    child.on('close', (code) => {
      const cleanStdout = stdout.trim()
      const cleanStderr = stderr.trim()
      if (code === 0) {
        finish({ success: true, output: cleanStdout })
      } else {
        finish({
          success: false,
          output: cleanStdout,
          error: cleanStderr || `ssh exited with code ${code ?? 'unknown'}`
        })
      }
    })

    child.stdin.on('error', () => {
      // The close/error handler returns the actionable SSH error.
    })
    child.stdin.end(options.stdin)
  })
}

async function buildCredentialPayload(tokenPath: string): Promise<string> {
  const tokenContent = await readFile(tokenPath)
  const parsed = JSON.parse(tokenContent.toString('utf8')) as { clientIdHash?: string }
  let registrationName = ''
  let registrationContent = Buffer.alloc(0)

  if (parsed.clientIdHash && /^[a-f0-9]{40}$/.test(parsed.clientIdHash)) {
    const candidateName = `${parsed.clientIdHash}.json`
    if (CLIENT_REGISTRATION_NAME.test(candidateName)) {
      try {
        registrationContent = await readFile(path.join(path.dirname(tokenPath), candidateName))
        registrationName = candidateName
      } catch {
        // Social login has no client registration. IdC sync still writes the token and reports no secret.
      }
    }
  }

  return [
    tokenContent.toString('base64'),
    registrationName,
    registrationContent.toString('base64'),
    ''
  ].join('\n')
}

export async function testRemoteKiroTargets(
  targets: string[],
  connectTimeoutSeconds: number = DEFAULT_REMOTE_KIRO_SYNC_SETTINGS.connectTimeoutSeconds
): Promise<RemoteKiroSyncTargetResult[]> {
  const settings = normalizeRemoteKiroSyncSettings({ enabled: true, targets, connectTimeoutSeconds })
  return Promise.all(settings.targets.map(async (target) => {
    const result = await runSshScript({
      target,
      connectTimeoutSeconds: settings.connectTimeoutSeconds,
      command: REMOTE_TEST_COMMAND,
      stdin: ''
    })
    return { target, success: result.success && result.output === 'ready', error: result.error }
  }))
}

export async function syncKiroAuthToRemotes(
  tokenPath: string,
  rawSettings: Partial<RemoteKiroSyncSettings> | null | undefined
): Promise<RemoteKiroSyncResult> {
  const settings = normalizeRemoteKiroSyncSettings(rawSettings)
  if (!settings.enabled) {
    return { success: true, skipped: true, reason: 'Remote SSH sync is disabled', results: [] }
  }
  if (settings.targets.length === 0) {
    return { success: false, reason: 'No Remote SSH targets configured', results: [] }
  }

  const payload = await buildCredentialPayload(tokenPath)
  const results = await Promise.all(settings.targets.map(async (target) => {
    const result = await runSshScript({
      target,
      connectTimeoutSeconds: settings.connectTimeoutSeconds,
      command: REMOTE_WRITE_COMMAND,
      stdin: payload
    })
    return {
      target,
      success: result.success && result.output === 'synced',
      error: result.error || (result.output === 'synced' ? undefined : 'Remote sync did not confirm completion')
    }
  }))

  return {
    success: results.every((result) => result.success),
    results
  }
}
