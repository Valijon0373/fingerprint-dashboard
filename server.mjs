import express from "express"
import cors from "cors"
import crypto from "crypto"
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server"
import { v4 as uuidv4 } from "uuid"

const app = express()
const port = Number(process.env.PORT || 4000)

/* ======================
   ENV CONFIG
====================== */

const rpName = process.env.RP_NAME || "FingerPrint Admin"
const staticRpID = process.env.RP_ID || ""
const staticExpectedOrigin = process.env.EXPECTED_ORIGIN || ""

function parseAllowedOrigins() {
  return (
    process.env.ALLOWED_ORIGINS ||
    "http://localhost:5173,http://localhost:3000"
  )
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
}

function getRequestOrigin(req) {
  const origin = req.headers.origin
  return typeof origin === "string" ? origin : undefined
}

function resolveExpectedOrigin(req) {
  if (staticExpectedOrigin) return staticExpectedOrigin

  const origin = getRequestOrigin(req)
  if (!origin) return undefined

  const allowedOrigins = parseAllowedOrigins()
  if (!allowedOrigins.includes(origin)) return undefined

  return origin
}

function resolveRpID(req) {
  if (staticRpID) return staticRpID

  const origin = resolveExpectedOrigin(req)
  if (!origin) return undefined

  try {
    return new URL(origin).hostname
  } catch {
    return undefined
  }
}

/* ======================
   CORS
====================== */

const allowedOrigins = parseAllowedOrigins()

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true)

      if (allowedOrigins.includes(origin)) {
        return callback(null, true)
      }

      console.log("CORS blocked:", origin)
      return callback(null, false)
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
)

/* Preflight fix */
app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    return res.sendStatus(200)
  }
  next()
})

app.use(express.json({ limit: "1mb" }))

/* ======================
   HEALTH CHECK
====================== */

app.get("/", (_req, res) => {
  res.send("WebAuthn API running")
})

app.get("/healthz", (_req, res) => {
  res.json({ ok: true })
})

/* ======================
   USER STORE
====================== */

const users = new Map()

function getUser(email) {
  if (!users.has(email)) {
    const webauthnId = crypto.randomBytes(16).toString("base64url")

    users.set(email, {
      id: uuidv4(),
      webauthnId,
      email,
      currentChallenge: undefined,
      credentials: [],
    })
  }

  return users.get(email)
}

/* ======================
   REGISTER OPTIONS
====================== */

app.post("/webauthn/register/options", (req, res) => {
  const { email } = req.body

  if (!email) {
    return res.status(400).json({ error: "email required" })
  }

  const user = getUser(email)

  const rpID = resolveRpID(req)

  if (!rpID) {
    return res.status(400).json({
      error: "rp_id_not_configured",
    })
  }

  const options = generateRegistrationOptions({
    rpName,
    rpID,
    userID: Buffer.from(user.webauthnId, "base64url"),
    userName: user.email,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  })

  user.currentChallenge = options.challenge

  res.json(options)
})

/* ======================
   REGISTER VERIFY
====================== */

app.post("/webauthn/register/verify", async (req, res) => {
  const { email, response } = req.body

  if (!email || !response) {
    return res.status(400).json({ error: "invalid payload" })
  }

  const user = getUser(email)

  try {
    const expectedOrigin = resolveExpectedOrigin(req)
    const rpID = resolveRpID(req)

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
    })

    const { verified, registrationInfo } = verification

    if (!verified || !registrationInfo) {
      return res.json({ verified: false })
    }

    const { credentialPublicKey, credentialID, counter } = registrationInfo

    user.credentials.push({
      id: Buffer.from(credentialID).toString("base64url"),
      publicKey: Buffer.from(credentialPublicKey).toString("base64url"),
      counter,
    })

    user.currentChallenge = undefined

    res.json({ verified: true })
  } catch (e) {
    console.error(e)
    res.status(400).json({ verified: false })
  }
})

/* ======================
   LOGIN OPTIONS
====================== */

app.post("/webauthn/login/options", (req, res) => {
  const { email } = req.body

  if (!email) {
    return res.status(400).json({ error: "email required" })
  }

  const user = getUser(email)

  const rpID = resolveRpID(req)

  const options = generateAuthenticationOptions({
    rpID,
    userVerification: "preferred",
    allowCredentials: user.credentials.map((cred) => ({
      id: Buffer.from(cred.id, "base64url"),
      type: "public-key",
    })),
  })

  user.currentChallenge = options.challenge

  res.json(options)
})

/* ======================
   LOGIN VERIFY
====================== */

app.post("/webauthn/login/verify", async (req, res) => {
  const { email, response } = req.body

  if (!email || !response) {
    return res.status(400).json({ error: "invalid payload" })
  }

  const user = getUser(email)

  const cred = user.credentials.find(
    (c) => c.id === response.rawId || c.id === response.id
  )

  try {
    const expectedOrigin = resolveExpectedOrigin(req)
    const rpID = resolveRpID(req)

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator:
        cred && {
          credentialID: Buffer.from(cred.id, "base64url"),
          credentialPublicKey: Buffer.from(cred.publicKey, "base64url"),
          counter: cred.counter,
        },
    })

    const { verified, authenticationInfo } = verification

    if (verified && authenticationInfo && cred) {
      cred.counter = authenticationInfo.newCounter
    }

    user.currentChallenge = undefined

    res.json({ verified: !!verified })
  } catch (e) {
    console.error(e)
    res.status(400).json({ verified: false })
  }
})

/* ======================
   SERVER
====================== */

app.listen(port, () => {
  console.log(`WebAuthn backend listening on port ${port}`)
})