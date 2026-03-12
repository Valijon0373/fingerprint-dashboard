# Fingerprint dashboard (WebAuthn demo)

This repo contains:
- A Vite + React UI
- A small Express backend that exposes WebAuthn endpoints (powered by `@simplewebauthn/server`)

## Run locally

Install deps:

```bash
npm i
```

Start backend:

```bash
npm run server
```

Start frontend (new terminal):

```bash
npm run dev
```

## Environment variables

### Frontend (Vite)

- `VITE_BACKEND_URL` (required in production; local default: `http://localhost:4000`)

### Backend (Express)

- `RP_NAME` (default: `FingerPrint Admin`)
- `RP_ID` (local default: `localhost`; **production: your real domain host** like `your-app.vercel.app`)
- `EXPECTED_ORIGIN` (local default: `http://localhost:5173`; **production: your real origin** like `https://your-app.vercel.app`)
- `ALLOWED_ORIGINS` (default: `http://localhost:5173,http://localhost:3000`; **production: include your Vercel origin(s)**)

If you deploy the frontend/backend to real domains, you MUST set these correctly (WebAuthn is strict):

- **Vercel (frontend)**: set `VITE_BACKEND_URL` to your Render backend HTTPS URL.
- **Render (backend)**:
  - set `ALLOWED_ORIGINS` to your Vercel site origin(s) (comma-separated)
  - set `EXPECTED_ORIGIN` to your Vercel site origin (or leave empty and rely on `Origin`, as long as it’s in `ALLOWED_ORIGINS`)
  - set `RP_ID` to your Vercel site host (no protocol) (or leave empty and rely on `Origin` host, as long as it’s in `ALLOWED_ORIGINS`)
```
