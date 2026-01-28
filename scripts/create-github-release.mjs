import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import path from 'node:path'

function getRepoSlug() {
  const raw = execSync('git config --get remote.origin.url', { encoding: 'utf-8' }).trim()
  if (!raw) throw new Error('Unable to determine git remote')
  if (raw.startsWith('git@')) {
    const match = raw.match(/git@[^:]+:([^/]+)\/(.+)\.git$/)
    if (!match) throw new Error('Unsupported git remote format')
    return `${match[1]}/${match[2]}`
  }
  const match = raw.match(/https?:\/\/[^/]+\/([^/]+)\/(.+?)(\.git)?$/)
  if (!match) throw new Error('Unsupported git remote format')
  return `${match[1]}/${match[2]}`
}

function getVersion() {
  const pkgPath = path.resolve(process.cwd(), 'package.json')
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
  if (!pkg?.version) throw new Error('package.json has no version')
  return String(pkg.version)
}

async function createRelease() {
  const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN
  if (!token) {
    // eslint-disable-next-line no-console
    console.warn('⚠️  GH_TOKEN or GITHUB_TOKEN not found. Skipping GitHub release creation.')
    // eslint-disable-next-line no-console
    console.warn('   Version bump and changelog generation completed successfully.')
    // eslint-disable-next-line no-console
    console.warn('   To create a GitHub release, set GH_TOKEN or GITHUB_TOKEN (Personal Access Token with repo scope).')
    // eslint-disable-next-line no-console
    console.warn('   In GitHub Actions, GITHUB_TOKEN is automatically available.')
    return
  }

  const repo = getRepoSlug()
  const version = getVersion()
  const tag = `v${version}`

  // codeql[js/file-data-in-outbound-network-request]: We only send the derived tag/name string
  // (from package.json version). We do not send raw file contents or user-provided file data.
  const res = await fetch(`https://api.github.com/repos/${repo}/releases`, {
    method: 'POST',
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'x-github-api-version': '2022-11-28',
    },
    body: JSON.stringify({
      tag_name: tag,
      name: tag,
      generate_release_notes: true,
    }),
  })

  if (res.status === 422) {
    // Release already exists; treat as success.
    return
  }

  if (!res.ok) {
    const text = await res.text()
    throw new Error(`GitHub release failed (${res.status}): ${text}`)
  }
}

createRelease().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err)
  process.exit(1)
})
