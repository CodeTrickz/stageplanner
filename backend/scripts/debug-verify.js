const fs = require('fs')
const crypto = require('crypto')
const Database = require('better-sqlite3')

function getLatestTokenFromLog() {
  const logPath = 'data/mails.log'
  const log = fs.readFileSync(logPath, 'utf8')
  const matches = [...log.matchAll(/token=([0-9a-f]+)/gi)]
  if (matches.length === 0) throw new Error('No token found in mails.log')
  return matches[matches.length - 1][1]
}

const token = getLatestTokenFromLog()
const hash = crypto.createHash('sha256').update(token).digest('hex')

console.log('latestToken:', token)
console.log('hash:', hash)

const db = new Database('data/dev.sqlite')
const rows = db
  .prepare(
    'select email, username, email_verified, email_verification_token_hash, email_verification_expires_at, created_at from users order by created_at desc',
  )
  .all()
console.log('users:', rows)

const match = db
  .prepare(
    'select email, username, email_verified, email_verification_expires_at from users where email_verification_token_hash = ?',
  )
  .get(hash)
console.log('matchByHash:', match)










