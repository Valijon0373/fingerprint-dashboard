import express from 'express'
import cors from 'cors'
import crypto from 'crypto'
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server'
import { v4 as uuidv4 } from 'uuid'

const app = express()
const port = Number(process.env.PORT || 4000)

// Relying Party (RP) configuration.
// - For local dev: RP_ID=localhost, EXPECTED_ORIGIN=http://localhost:5173
// - For prod: set RP_ID/EXPECTED_ORIGIN to your actual domain/origin.
const rpName = process.env.RP_NAME || 'FingerPrint Admin'
const staticRpID = process.env.RP_ID || ''
const staticExpectedOrigin = process.env.EXPECTED_ORIGIN || ''

function parseAllowedOrigins() {
  return (process.env.ALLOWED_ORIGINS || 'http://localhost:5173,http://localhost:3000')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

function getRequestOrigin(req) {
  const origin = req.headers.origin
  return typeof origin === 'string' ? origin : undefined
}

function resolveExpectedOrigin(req) {
  // Prefer explicit config; otherwise use the request Origin (if allowed).
  if (staticExpectedOrigin) return staticExpectedOrigin

  const origin = getRequestOrigin(req)
  if (!origin) return undefined

  const allowedOrigins = parseAllowedOrigins()
  if (!allowedOrigins.includes(origin)) return undefined

  return origin
}

function resolveRpID(req) {
  // Prefer explicit config; otherwise derive from the allowed request Origin host.
  if (staticRpID) return staticRpID

  const origin = resolveExpectedOrigin(req)
  if (!origin) return undefined

  try {
    return new URL(origin).hostname
  } catch {
    return undefined
  }
}

app.use(
  cors({
    origin: (origin, callback) => {
      const allowedOrigins = parseAllowedOrigins()

      // origin bo'lmasa ham (masalan, Postman) ruxsat beramiz
      if (!origin) return callback(null, true)

      if (allowedOrigins.includes(origin)) {
        callback(null, true)
      } else {
        callback(new Error('Not allowed by CORS'))
      }
    },
    credentials: true,
  }),
)
app.use(express.json({ limit: '1mb' }))

// In-memory user store (demo only)
const users = new Map()

function getUser(email) {
  if (!users.has(email)) {
    const webauthnId = crypto.randomBytes(16).toString('base64url')
    users.set(email, {
      id: uuidv4(), // ilova ichidagi user ID (string)
      webauthnId, // WebAuthn uchun binar ID (base64url)
      email,
      currentChallenge: undefined,
      credentials: [],
    })
  }
  return users.get(email)
}

app.post('/webauthn/register/options', (req, res) => {
  try {
    const { email } = req.body
    if (!email) {
      return res.status(400).json({ error: 'email required' })
    }
    const user = getUser(email)

    const rpID = resolveRpID(req)
    if (!rpID) {
      return res.status(400).json({
        error: 'rp_id_not_configured',
        message:
          'RP_ID is not configured and could not be derived from an allowed Origin. Set RP_ID and ALLOWED_ORIGINS for production.',
      })
    }

    const options = generateRegistrationOptions({
      rpName,
      rpID,
      userID: Buffer.from(user.webauthnId, 'base64url'),
      userName: user.email,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    })

    user.currentChallenge = options.challenge
    return res.json(options)
  } catch (e) {
    console.error('Error in /webauthn/register/options:', e)
    return res.status(500).json({ error: 'register_options_failed', message: e.message })
  }
})

app.post('/webauthn/register/verify', async (req, res) => {
  const { email, response } = req.body
  if (!email || !response) {
    return res.status(400).json({ error: 'invalid payload' })
  }
  const user = getUser(email)

  try {
    const expectedOrigin = resolveExpectedOrigin(req)
    const rpID = resolveRpID(req)
    if (!expectedOrigin || !rpID) {
      return res.status(400).json({
        verified: false,
        error:
          'origin_or_rpid_not_configured: set EXPECTED_ORIGIN and RP_ID (or configure ALLOWED_ORIGINS so they can be derived)',
      })
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
    })

    const { verified, registrationInfo } = verification
    if (!verified || !registrationInfo) {
      return res.status(400).json({ verified: false })
    }

    const { credentialPublicKey, credentialID, counter } = registrationInfo

    user.credentials.push({
      id: Buffer.from(credentialID).toString('base64url'),
      publicKey: Buffer.from(credentialPublicKey).toString('base64url'),
      counter,
    })

    user.currentChallenge = undefined
    return res.json({ verified: true })
  } catch (e) {
    console.error(e)
    return res.status(400).json({ verified: false, error: e.message })
  }
})

app.post('/webauthn/login/options', (req, res) => {
  const { email } = req.body
  if (!email) {
    return res.status(400).json({ error: 'email required' })
  }
  const user = getUser(email)

  const rpID = resolveRpID(req)
  if (!rpID) {
    return res.status(400).json({
      error: 'rp_id_not_configured',
      message:
        'RP_ID is not configured and could not be derived from an allowed Origin. Set RP_ID and ALLOWED_ORIGINS for production.',
    })
  }

  const options = generateAuthenticationOptions({
    rpID,
    userVerification: 'preferred',
    allowCredentials: user.credentials.map((cred) => ({
      id: Buffer.from(cred.id, 'base64url'),
      type: 'public-key',
    })),
  })

  user.currentChallenge = options.challenge
  return res.json(options)
})

app.post('/webauthn/login/verify', async (req, res) => {
  const { email, response } = req.body
  if (!email || !response) {
    return res.status(400).json({ error: 'invalid payload' })
  }
  const user = getUser(email)

  const cred = user.credentials.find(
    (c) => c.id === response.rawId || c.id === response.id,
  )

  try {
    const expectedOrigin = resolveExpectedOrigin(req)
    const rpID = resolveRpID(req)
    if (!expectedOrigin || !rpID) {
      return res.status(400).json({
        verified: false,
        error:
          'origin_or_rpid_not_configured: set EXPECTED_ORIGIN and RP_ID (or configure ALLOWED_ORIGINS so they can be derived)',
      })
    }

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: cred && {
        credentialID: Buffer.from(cred.id, 'base64url'),
        credentialPublicKey: Buffer.from(cred.publicKey, 'base64url'),
        counter: cred.counter,
      },
    })

    const { verified, authenticationInfo } = verification
    if (verified && authenticationInfo && cred) {
      cred.counter = authenticationInfo.newCounter
    }
    user.currentChallenge = undefined
    return res.json({ verified: !!verified })
  } catch (e) {
    console.error(e)
    return res.status(400).json({ verified: false, error: e.message })
  }
})

app.listen(port, () => {
  console.log(`WebAuthn backend listening on port ${port}`)
})

