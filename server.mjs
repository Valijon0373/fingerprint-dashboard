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
const port = 4000

// Relying Party (RP) ma'lumotlari (prod uchun to'g'ridan-to'g'ri yozib qo'yamiz)
// Frontend domening (brauzerda ishlatayotgan haqiqiy URL):
//   https://fingerprint.vercel.app
const rpName = 'FingerPrint Admin'
const rpID = 'fingerprint.vercel.app'
const expectedOrigin = 'https://fingerprint.vercel.app'

app.use(
  cors({
    origin: (origin, callback) => {
      const allowedOrigins = [
        // Dev
        'http://localhost:5173',
        'http://localhost:3000',
        // Prod (ikkala Vercel domeningni ham qo'yamiz)
        'https://fingerprint.vercel.app',
        'https://fingerprint-dashboard-sable.vercel.app',
      ]

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
  console.log(`WebAuthn backend listening at http://localhost:${port}`)
})

