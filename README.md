# tabs-pro-back

Backend for TabsPro — upload, store, share and download guitar tab files (Guitar Pro `.gp/.gp3/.gp4/.gp5/.gpx`, `.tex`). Files live in S3 (or any S3-compatible bucket); metadata in MySQL.

Built with [Hono](https://hono.dev) on Node, Prisma + MySQL, and the AWS S3 SDK. The whole API is a single file: [src/index.ts](src/index.ts).

## Features

- Email/password auth + password reset (JWT, 7-day expiry)
- Google OAuth login
- Tab upload / list / get / update / delete with per-user S3 keys
- Presigned download URLs (1h expiry)
- Public read-only share links via share token
- In-memory rate limiting (100 req/min per IP)

## Requirements

- Node 18+ (uses native `fetch`, `FormData`, `File`)
- MySQL
- An S3 bucket (real AWS or S3-compatible, e.g. Railway)

## Setup

```bash
npm install
cp .env.example .env   # then fill in values
npm run db:push        # create tables from prisma/schema.prisma
npm run dev            # http://localhost:3001
```

### Environment

See [.env.example](.env.example). Key vars: `PORT`, `JWT_SECRET`, `MYSQL_URL`, AWS creds + `S3_BUCKET`, `CORS_ORIGIN`, `MAX_FILE_SIZE` (bytes, default 50MB), and the `GOOGLE_*` OAuth keys. Leave `S3_ENDPOINT` empty for real AWS; set it for S3-compatible providers.

## Scripts

| Script | Action |
|---|---|
| `npm run dev` | Watch mode (tsx) |
| `npm run build` | Compile to `dist/` |
| `npm start` | Run compiled build |
| `npm run db:generate` | Prisma client |
| `npm run db:push` | Push schema to DB |
| `npm run db:migrate` | Dev migration |

## API

All routes prefixed `/api`. Protected routes need `Authorization: Bearer <token>`.

**Auth (public)**
- `POST /auth/register` — `{ email, password }` → `{ token, user }`
- `POST /auth/login` — `{ email, password }` → `{ token, user }`
- `POST /auth/forgot-password` — `{ email }` (reset link logged to console — see note below)
- `POST /auth/reset-password` — `{ token, password }`
- `GET /auth/google` → redirects to Google
- `GET /auth/google/callback` → redirects to `CORS_ORIGIN` with `?token=`

**Tabs (protected)**
- `GET /auth/me` — current user + tab count
- `POST /tabs` — multipart `file` upload
- `GET /tabs` — list user's tabs
- `GET /tabs/:id` — tab metadata
- `PUT /tabs/:id` — replace file (multipart `file`)
- `DELETE /tabs/:id` — delete tab + S3 object
- `POST /tabs/:id/share` — create/return share token
- `GET /tabs/:id/download` — presigned download URL

**Share (public)**
- `GET /shared/:token` — shared tab metadata
- `GET /shared/:token/download` — presigned download URL

## Notes

- Password reset emails are `console.log`'d, not sent — wire up SMTP (e.g. nodemailer) for production.
- Rate limiting is in-memory — add Redis if running multiple instances.
