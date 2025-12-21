import nodemailer from 'nodemailer'
import fs from 'node:fs'
import path from 'node:path'

type Mail = { to: string; subject: string; text?: string; html?: string }

function transportFromEnv() {
  const host = process.env.SMTP_HOST
  const user = process.env.SMTP_USER
  const pass = process.env.SMTP_PASS
  const port = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587
  const secure = process.env.SMTP_SECURE === 'true'

  if (!host || !user || !pass) return null
  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
  })
}

export async function sendMail(mail: Mail) {
  const t = transportFromEnv()
  if (t) {
    await t.sendMail({
      from: process.env.MAIL_FROM || process.env.SMTP_USER,
      to: mail.to,
      subject: mail.subject,
      text: mail.text,
      html: mail.html,
    })
    return { mode: 'smtp' as const }
  }

  // Dev fallback: log to file + console
  const p = path.resolve(process.cwd(), 'data', 'mails.log')
  fs.mkdirSync(path.dirname(p), { recursive: true })
  const entry = [
    `--- ${new Date().toISOString()} ---`,
    `TO: ${mail.to}`,
    `SUBJECT: ${mail.subject}`,
    mail.text ? `TEXT:\n${mail.text}` : '',
    mail.html ? `HTML:\n${mail.html}` : '',
    '',
  ].join('\n')
  fs.appendFileSync(p, entry, 'utf-8')
  // eslint-disable-next-line no-console
  console.log(`DEV MAIL -> ${mail.to}: ${mail.subject} (see ${p})`)
  return { mode: 'dev_log' as const, path: p }
}









