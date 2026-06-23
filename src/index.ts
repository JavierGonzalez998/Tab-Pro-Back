import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { jwt, sign } from 'hono/jwt'
import { serve } from '@hono/node-server'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'
import { randomUUID } from 'crypto'
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'

// --- Config ---
const PORT = parseInt(process.env.PORT || '3001')
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'
const S3_BUCKET = process.env.S3_BUCKET || 'tabs-pro-files'
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000'
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE || '52428800')
const GOOGLE_REDIRECT = process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/api/auth/google/callback`

// --- Database ---
const prisma = new PrismaClient()

// --- S3 ---
// ponytail: endpoint + forcePathStyle enable Railway/S3-compatible buckets
const s3 = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  ...(process.env.S3_ENDPOINT ? {
    endpoint: process.env.S3_ENDPOINT,
    forcePathStyle: process.env.S3_FORCE_PATH_STYLE !== 'false',
  } : {}),
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || '',
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || '',
  },
})

// --- Rate limiter ---
// ponytail: in-memory rate limiter, add Redis if multi-instance
const rateMap = new Map<string, { count: number; reset: number }>()
const RATE_MAX = 100
setInterval(() => {
  const now = Date.now()
  for (const [ip, r] of rateMap) { if (now > r.reset) rateMap.delete(ip) }
}, 300_000).unref()

function checkRate(ip: string): boolean {
  const now = Date.now()
  const r = rateMap.get(ip)
  if (!r || now > r.reset) { rateMap.set(ip, { count: 1, reset: now + 60_000 }); return true }
  if (r.count >= RATE_MAX) return false
  r.count++
  return true
}

// --- App ---
const app = new Hono()

app.use('*', cors({
  origin: CORS_ORIGIN,
  credentials: true,
  allowHeaders: ['Authorization', 'Content-Type'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
}))

app.use('*', async (c, next) => {
  const ip = c.req.header('x-forwarded-for') || '127.0.0.1'
  if (!checkRate(ip)) return c.json({ error: 'Too many requests' }, 429)
  await next()
})

// --- Public auth ---

app.post('/api/auth/register', async (c) => {
  const { email, password } = await c.req.json()
  if (!email || !password) return c.json({ error: 'Email and password required' }, 400)
  if (password.length < 6) return c.json({ error: 'Password must be at least 6 characters' }, 400)

  const existing = await prisma.user.findUnique({ where: { email } })
  if (existing) return c.json({ error: 'Email already registered' }, 409)

  const hash = await bcrypt.hash(password, 10)
  const user = await prisma.user.create({
    data: { email, password: hash },
  })

  const token = await sign({ sub: user.id, exp: Math.floor(Date.now() / 1000) + 7 * 86400 }, JWT_SECRET)
  return c.json({ token, user: { id: user.id, email: user.email } }, 201)
})

app.post('/api/auth/login', async (c) => {
  const { email, password } = await c.req.json()
  if (!email || !password) return c.json({ error: 'Email and password required' }, 400)

  const user = await prisma.user.findUnique({ where: { email } })
  if (!user || !user.password)
    return c.json({ error: user?.oauthProvider ? `Please sign in with ${user.oauthProvider}` : 'Invalid credentials' }, 401)
  if (!(await bcrypt.compare(password, user.password)))
    return c.json({ error: 'Invalid credentials' }, 401)

  const token = await sign({ sub: user.id, exp: Math.floor(Date.now() / 1000) + 7 * 86400 }, JWT_SECRET)
  return c.json({ token, user: { id: user.id, email: user.email } })
})

app.post('/api/auth/forgot-password', async (c) => {
  const { email } = await c.req.json()
  const user = await prisma.user.findUnique({ where: { email } })
  // ponytail: always ok to prevent email enumeration
  if (!user || user.oauthProvider) return c.json({ ok: true })

  const resetToken = randomUUID()
  await prisma.user.update({
    where: { email },
    data: { resetToken, resetExpires: new Date(Date.now() + 3600_000) },
  })

  // ponytail: console.log instead of SMTP; configure nodemailer for production
  console.log(`[reset] ${CORS_ORIGIN}/reset-password/${resetToken}`)
  return c.json({ ok: true })
})

app.post('/api/auth/reset-password', async (c) => {
  const { token, password } = await c.req.json()
  if (!token || !password || password.length < 6) return c.json({ error: 'Invalid request' }, 400)

  const user = await prisma.user.findFirst({
    where: { resetToken: token, resetExpires: { gt: new Date() } },
  })
  if (!user) return c.json({ error: 'Invalid or expired token' }, 400)

  const hash = await bcrypt.hash(password, 10)
  await prisma.user.update({
    where: { id: user.id },
    data: { password: hash, resetToken: null, resetExpires: null },
  })
  return c.json({ ok: true })
})

// --- Google OAuth ---

app.get('/api/auth/google', (c) => {
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID || '',
    redirect_uri: GOOGLE_REDIRECT,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'consent',
  })
  return c.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`)
})

app.get('/api/auth/google/callback', async (c) => {
  const code = c.req.query('code')
  if (!code) return c.redirect(`${CORS_ORIGIN}/login?error=oauth_failed`)

  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID || '',
        client_secret: process.env.GOOGLE_CLIENT_SECRET || '',
        redirect_uri: GOOGLE_REDIRECT,
        grant_type: 'authorization_code',
      }),
    })
    const tokens = await tokenRes.json() as any
    if (!tokens.access_token) throw new Error('Token exchange failed')

    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    })
    const profile = await userRes.json() as any

    let oauthUser = await prisma.user.findFirst({
      where: { oauthProvider: 'google', oauthId: profile.id },
    })

    if (!oauthUser) {
      const existing = await prisma.user.findUnique({ where: { email: profile.email } })
      if (existing) {
        oauthUser = await prisma.user.update({
          where: { id: existing.id },
          data: { oauthProvider: 'google', oauthId: profile.id },
        })
      } else {
        oauthUser = await prisma.user.create({
          data: { email: profile.email, oauthProvider: 'google', oauthId: profile.id },
        })
      }
    }

    const jwtToken = await sign({ sub: oauthUser.id, exp: Math.floor(Date.now() / 1000) + 7 * 86400 }, JWT_SECRET)
    return c.redirect(`${CORS_ORIGIN}/oauth/callback?token=${jwtToken}`)
  } catch {
    return c.redirect(`${CORS_ORIGIN}/login?error=oauth_failed`)
  }
})

// --- Public share routes (read-only) ---

app.get('/api/shared/:token', async (c) => {
  const tab = await prisma.tab.findUnique({ where: { shareToken: c.req.param('token') } })
  if (!tab) return c.json({ error: 'Not found' }, 404)
  return c.json(mapTab(tab))
})

app.get('/api/shared/:token/download', async (c) => {
  const tab = await prisma.tab.findUnique({ where: { shareToken: c.req.param('token') } })
  if (!tab) return c.json({ error: 'Not found' }, 404)
  const url = await presignDownload(tab)
  return c.json({ url })
})

// --- Protected routes ---

const api = new Hono()
api.use('*', jwt({ secret: JWT_SECRET, alg: 'HS256' }))

api.get('/auth/me', async (c) => {
  const { sub } = c.get('jwtPayload') as { sub: string }
  const user = await prisma.user.findUnique({
    where: { id: sub },
    select: { id: true, email: true, oauthProvider: true, createdAt: true },
  })
  if (!user) return c.json({ error: 'User not found' }, 404)

  const tabCount = await prisma.tab.count({ where: { userId: sub } })
  return c.json({ ...user, tabCount })
})

api.post('/tabs', async (c) => {
  const { sub } = c.get('jwtPayload') as { sub: string }
  const formData = await c.req.formData()
  const file = formData.get('file') as File | null
  if (!file) return c.json({ error: 'File required' }, 400)

  const existingCount = await prisma.tab.count({ where: { userId: sub } })
  if (existingCount >= 5) return c.json({ error: 'Limit of 5 tabs reached. Delete some to upload more.' }, 403)

  const ext = file.name.slice(file.name.lastIndexOf('.')).toLowerCase()
  if (!['.gp', '.gp3', '.gp4', '.gp5', '.gpx', '.tex'].includes(ext))
    return c.json({ error: 'Invalid file type' }, 400)

  const buffer = Buffer.from(await file.arrayBuffer())
  if (buffer.length > MAX_FILE_SIZE)
    return c.json({ error: `File exceeds ${MAX_FILE_SIZE / 1048576}MB limit` }, 413)

  const id = randomUUID()
  const s3Key = `tabs/${sub}/${id}${ext}`

  await s3.send(new PutObjectCommand({ Bucket: S3_BUCKET, Key: s3Key, Body: buffer }))
  const tab = await prisma.tab.create({
    data: {
      id, userId: sub,
      name: file.name.replace(ext, ''),
      originalName: file.name,
      s3Key, fileSize: buffer.length,
    },
  })

  return c.json({ id: tab.id, name: tab.name, originalName: tab.originalName, fileSize: tab.fileSize }, 201)
})

api.get('/tabs', async (c) => {
  const { sub } = c.get('jwtPayload') as { sub: string }
  const tabs = await prisma.tab.findMany({
    where: { userId: sub },
    orderBy: { createdAt: 'desc' },
  })
  return c.json(tabs.map(mapTab))
})

api.get('/tabs/:id', async (c) => {
  const { sub } = c.get('jwtPayload') as { sub: string }
  const tab = await prisma.tab.findUnique({ where: { id: c.req.param('id') } })
  if (!tab || tab.userId !== sub) return c.json({ error: 'Not found' }, 404)
  return c.json(mapTab(tab))
})

api.delete('/tabs/:id', async (c) => {
  const { sub } = c.get('jwtPayload') as { sub: string }
  const tab = await prisma.tab.findUnique({ where: { id: c.req.param('id') } })
  if (!tab || tab.userId !== sub) return c.json({ error: 'Not found' }, 404)

  await s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: tab.s3Key }))
  await prisma.tab.delete({ where: { id: tab.id } })
  return c.json({ ok: true })
})

api.put('/tabs/:id', async (c) => {
  const { sub } = c.get('jwtPayload') as { sub: string }
  const tab = await prisma.tab.findUnique({ where: { id: c.req.param('id') } })
  if (!tab || tab.userId !== sub) return c.json({ error: 'Not found' }, 404)

  const formData = await c.req.formData()
  const file = formData.get('file') as File | null
  if (!file) return c.json({ error: 'File required' }, 400)

  const buffer = Buffer.from(await file.arrayBuffer())
  if (buffer.length > MAX_FILE_SIZE)
    return c.json({ error: `File exceeds ${MAX_FILE_SIZE / 1048576}MB limit` }, 413)

  // ponytail: delete old S3 object, upload new one, update metadata
  await s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: tab.s3Key }))
  const ext = file.name.slice(file.name.lastIndexOf('.')).toLowerCase()
  const s3Key = `tabs/${sub}/${tab.id}${ext}`
  await s3.send(new PutObjectCommand({ Bucket: S3_BUCKET, Key: s3Key, Body: buffer }))

  await prisma.tab.update({
    where: { id: tab.id },
    data: { name: file.name.replace(ext, ''), originalName: file.name, s3Key, fileSize: buffer.length },
  })

  return c.json({ ok: true })
})

api.post('/tabs/:id/share', async (c) => {
  const { sub } = c.get('jwtPayload') as { sub: string }
  const tab = await prisma.tab.findUnique({ where: { id: c.req.param('id') } })
  if (!tab || tab.userId !== sub) return c.json({ error: 'Not found' }, 404)

  const shareToken = tab.shareToken || randomUUID()
  if (!tab.shareToken) {
    await prisma.tab.update({ where: { id: tab.id }, data: { shareToken } })
  }

  return c.json({ shareToken, shareUrl: `${CORS_ORIGIN}/shared/${shareToken}` })
})

api.get('/tabs/:id/download', async (c) => {
  const { sub } = c.get('jwtPayload') as { sub: string }
  const tab = await prisma.tab.findUnique({ where: { id: c.req.param('id') } })
  if (!tab || tab.userId !== sub) return c.json({ error: 'Not found' }, 404)

  const url = await presignDownload(tab)
  return c.json({ url })
})

app.route('/api', api)

// --- Helpers ---

function mapTab(t: { id: string; name: string; originalName: string; fileSize: number; shareToken: string | null; createdAt: Date }) {
  return {
    id: t.id,
    name: t.name,
    originalName: t.originalName,
    fileSize: t.fileSize,
    shared: !!t.shareToken,
    shareToken: t.shareToken || undefined,
    createdAt: t.createdAt.toISOString(),
  }
}

async function presignDownload(tab: { s3Key: string; originalName: string }) {
  return getSignedUrl(s3, new GetObjectCommand({
    Bucket: S3_BUCKET,
    Key: tab.s3Key,
    ResponseContentDisposition: `attachment; filename="${tab.originalName}"`,
  }), { expiresIn: 3600 })
}

// --- Graceful shutdown ---
process.on('SIGINT', async () => { await prisma.$disconnect(); process.exit(0) })
process.on('SIGTERM', async () => { await prisma.$disconnect(); process.exit(0) })

// --- Start ---
serve({ fetch: app.fetch, port: PORT }, (info) => {
  console.log(`TabsPro backend → http://localhost:${info.port}`)
})
