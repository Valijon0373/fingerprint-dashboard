import { useState } from 'react'
import { IoMdFingerPrint } from 'react-icons/io'
import { TbFaceId } from 'react-icons/tb'

type AuthMode = 'password' | 'biometric'

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [authMode, setAuthMode] = useState<AuthMode>('password')
  const [bioLoading, setBioLoading] = useState(false)
  const [bioError, setBioError] = useState<string | null>(null)

  const backendUrl = 'https://fingerprint-dashboard.onrender.com'

  function base64urlToBuffer(base64url?: string): Uint8Array {
    if (!base64url) {
      throw new Error('base64url is undefined')
    }

    const padding = '='.repeat((4 - (base64url.length % 4)) % 4)
    const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/')

    const rawData = window.atob(base64)
    return Uint8Array.from([...rawData].map((c) => c.charCodeAt(0)))
  }

  function bufferToBase64url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer)
    let binary = ''
    for (let i = 0; i < bytes.byteLength; i += 1) {
      binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
  }

  async function handleBiometricLogin() {
    try {
      setBioLoading(true)
      setBioError(null)

      const emailInput = document.getElementById('email') as HTMLInputElement | null
      const email = emailInput?.value || 'admin@example.com'

      const hasPasskey = window.localStorage.getItem(`passkey-${email}`) === '1'

      if (!('credentials' in navigator)) {
        setBioError('Bu brauzer WebAuthn ni qo‘llab-quvvatlamaydi')
        return
      }

      if (!hasPasskey) {
        const regOptsRes = await fetch(`${backendUrl}/webauthn/register/options`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        })
        const regOpts = await regOptsRes.json()

        regOpts.challenge = base64urlToBuffer(regOpts.challenge).buffer
        regOpts.user.id = base64urlToBuffer(regOpts.user.id).buffer
        if (regOpts.excludeCredentials) {
          regOpts.excludeCredentials = regOpts.excludeCredentials.map((c: any) => ({
            ...c,
            id: base64urlToBuffer(c.id),
          }))
        }

        const credential = (await navigator.credentials.create({
          publicKey: regOpts,
        })) as PublicKeyCredential

        const regVerificationRes = await fetch(
          `${backendUrl}/webauthn/register/verify`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              email,
              response: {
                id: credential.id,
                rawId: bufferToBase64url(credential.rawId),
                type: credential.type,
                response: {
                  clientDataJSON: bufferToBase64url(
                    (credential.response as AuthenticatorAttestationResponse).clientDataJSON,
                  ),
                  attestationObject: bufferToBase64url(
                    (credential.response as AuthenticatorAttestationResponse).attestationObject!,
                  ),
                },
              },
            }),
          },
        )

        const regVerification = await regVerificationRes.json()
        if (!regVerification.verified) {
          setBioError('Biometrik ro‘yxatdan o‘tish muvaffaqiyatsiz')
          return
        }
        window.localStorage.setItem(`passkey-${email}`, '1')
      }

      const authOptsRes = await fetch(`${backendUrl}/webauthn/login/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      })
        const authOpts = await authOptsRes.json()

        authOpts.challenge = base64urlToBuffer(authOpts.challenge).buffer
      if (authOpts.allowCredentials) {
          authOpts.allowCredentials = authOpts.allowCredentials.map((c: any) => ({
            ...c,
            id: base64urlToBuffer(c.id).buffer,
          }))
      }

      const assertion = (await navigator.credentials.get({
        publicKey: authOpts,
      })) as PublicKeyCredential

      const authVerificationRes = await fetch(
        `${backendUrl}/webauthn/login/verify`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email,
            response: {
              id: assertion.id,
              rawId: bufferToBase64url(assertion.rawId),
              type: assertion.type,
              response: {
                clientDataJSON: bufferToBase64url(
                  (assertion.response as AuthenticatorAssertionResponse).clientDataJSON,
                ),
                authenticatorData: bufferToBase64url(
                  (assertion.response as AuthenticatorAssertionResponse).authenticatorData,
                ),
                signature: bufferToBase64url(
                  (assertion.response as AuthenticatorAssertionResponse).signature,
                ),
                userHandle:
                  (assertion.response as AuthenticatorAssertionResponse)
                    .userHandle &&
                  bufferToBase64url(
                    (assertion.response as AuthenticatorAssertionResponse)
                      .userHandle!,
                  ),
              },
            },
          }),
        },
      )

      const authVerification = await authVerificationRes.json()
      if (!authVerification.verified) {
        setBioError('Biometrik tasdiqlash muvaffaqiyatsiz')
        return
      }

      setIsAuthenticated(true)
    } catch (error) {
      console.error(error)
      setBioError('Biometrik jarayonda xato yuz berdi')
    } finally {
      setBioLoading(false)
    }
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center px-4">
        <div className="w-full max-w-md space-y-8">
          <div className="text-center space-y-2">
            <h1 className="text-3xl font-bold tracking-tight">
              FingerPrint Admin
            </h1>
            <p className="text-sm text-slate-400">
              Avval login va parol, keyin FaceID yoki Fingerprint orqali kirish.
            </p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-900/40 p-6 space-y-6">
            <div className="flex rounded-full bg-slate-800 p-1 text-xs">
              <button
                type="button"
                onClick={() => setAuthMode('password')}
                className={`flex-1 rounded-full py-1.5 transition ${
                  authMode === 'password'
                    ? 'bg-primary-500 text-white shadow'
                    : 'text-slate-400 hover:text-slate-100'
                }`}
              >
                Login / Parol
              </button>
              <button
                type="button"
                onClick={() => setAuthMode('biometric')}
                className={`flex-1 rounded-full py-1.5 transition ${
                  authMode === 'biometric'
                    ? 'bg-primary-500 text-white shadow'
                    : 'text-slate-400 hover:text-slate-100'
                }`}
              >
                FaceID / Fingerprint
              </button>
            </div>

            {authMode === 'password' ? (
              <form
                className="space-y-4"
                onSubmit={(e) => {
                  e.preventDefault()
                  // Demo uchun: har doim success
                  setIsAuthenticated(true)
                }}
              >
                <div className="space-y-1.5">
                  <label
                    htmlFor="email"
                    className="text-xs font-medium text-slate-300"
                  >
                    Login (email yoki user)
                  </label>
                  <input
                    id="email"
                    type="email"
                    required
                    className="w-full rounded-xl border border-slate-700 bg-slate-900/70 px-3 py-2.5 text-sm text-white placeholder-slate-500 outline-none focus:border-primary-500 focus:ring-2 focus:ring-primary-500/40"
                    placeholder="admin@example.com"
                  />
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor="password"
                    className="text-xs font-medium text-slate-300"
                  >
                    Parol
                  </label>
                  <input
                    id="password"
                    type="password"
                    required
                    className="w-full rounded-xl border border-slate-700 bg-slate-900/70 px-3 py-2.5 text-sm text-white placeholder-slate-500 outline-none focus:border-primary-500 focus:ring-2 focus:ring-primary-500/40"
                    placeholder="••••••••"
                  />
                </div>

                <button
                  type="submit"
                  className="mt-2 w-full rounded-xl bg-primary-500 hover:bg-primary-600 text-sm font-semibold py-2.5 transition shadow-lg shadow-primary-500/30"
                >
                  Kirish
                </button>
              </form>
            ) : (
              <div className="space-y-4">
                <p className="text-xs text-slate-400">
                  FaceID yoki Fingerprint tugmasini bossangiz, brauzer orqali
                  WebAuthn (passkey) ochiladi. Birinchi marta ro‘yxatdan
                  o‘tasiz, keyingi safar to‘g‘ridan-to‘g‘ri biometrik bilan
                  kirasiz.
                </p>
                {bioError && (
                  <p className="text-xs text-red-400">{bioError}</p>
                )}
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={handleBiometricLogin}
                    className="flex flex-col items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900/70 px-3 py-4 text-xs hover:border-primary-500 hover:bg-slate-900 transition"
                  >
                    <span className="inline-flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 text-slate-900">
                      <TbFaceId className="h-7 w-7" />
                    </span>
                    <span className="font-medium text-slate-100">
                      {bioLoading ? 'Kutilmoqda...' : 'Face ID bilan'}
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={handleBiometricLogin}
                    className="flex flex-col items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900/70 px-3 py-4 text-xs hover:border-primary-500 hover:bg-slate-900 transition"
                  >
                    <span className="inline-flex h-12 w-12 items-center justify-center rounded-full bg-blue-50 text-blue-500">
                      <IoMdFingerPrint className="h-7 w-7" />
                    </span>
                    <span className="font-medium text-slate-100">
                      {bioLoading ? 'Kutilmoqda...' : 'Fingerprint bilan'}
                    </span>
                  </button>
                </div>
              </div>
            )}
          </div>

          <p className="text-center text-[11px] text-slate-500">
            Demo rejim · Keyinchalik backend qo‘shib, haqiqiy WebAuthn
            (Windows Hello / Touch ID / Android biometrika) ulash mumkin.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-950 text-white flex">
      <aside className="hidden md:flex w-64 flex-col border-r border-slate-800 bg-slate-950/80">
        <div className="px-6 py-4 border-b border-slate-800">
          <div className="text-lg font-semibold tracking-tight">
            FingerPrint Admin
          </div>
          <div className="text-[11px] text-slate-500">
            Secure dashboard (demo)
          </div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1 text-sm">
          <button className="w-full flex items-center gap-2 rounded-lg px-3 py-2 bg-slate-800 text-white">
            <span>Dashboard</span>
          </button>
          <button className="w-full flex items-center gap-2 rounded-lg px-3 py-2 text-slate-300 hover:bg-slate-900">
            <span>Users</span>
          </button>
          <button className="w-full flex items-center gap-2 rounded-lg px-3 py-2 text-slate-300 hover:bg-slate-900">
            <span>Settings</span>
          </button>
        </nav>
        <div className="px-4 py-3 border-t border-slate-800 text-xs text-slate-500">
          <button
            type="button"
            onClick={() => setIsAuthenticated(false)}
            className="text-slate-300 hover:text-red-400"
          >
            Chiqish
          </button>
        </div>
      </aside>

      <main className="flex-1 min-w-0">
        <header className="flex items-center justify-between px-4 md:px-8 py-4 border-b border-slate-800 bg-slate-950/80">
          <div>
            <h2 className="text-xl font-semibold tracking-tight">
              Xush kelibsiz, Admin
            </h2>
            <p className="text-xs text-slate-500">
              Bu yerda siz umumiy statistikani ko‘rasiz.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex flex-col items-end text-xs">
              <span className="font-medium text-slate-200">Admin User</span>
              <span className="text-slate-500">Super admin</span>
            </div>
            <div className="h-9 w-9 rounded-full bg-gradient-to-br from-primary-500 to-emerald-500 flex items-center justify-center text-xs font-semibold">
              A
            </div>
          </div>
        </header>

        <section className="px-4 md:px-8 py-6 space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
              <p className="text-xs text-slate-400">Bugungi loginlar</p>
              <p className="mt-2 text-2xl font-semibold">128</p>
              <p className="mt-1 text-[11px] text-emerald-400">
                +12% o‘tgan haftaga nisbatan
              </p>
            </div>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
              <p className="text-xs text-slate-400">Biometrik loginlar</p>
              <p className="mt-2 text-2xl font-semibold">82</p>
              <p className="mt-1 text-[11px] text-slate-400">
                FaceID, Fingerprint va Windows Hello
              </p>
            </div>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
              <p className="text-xs text-slate-400">Faol foydalanuvchilar</p>
              <p className="mt-2 text-2xl font-semibold">534</p>
              <p className="mt-1 text-[11px] text-slate-400">
                Oxirgi 24 soat ichida
              </p>
            </div>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
              <p className="text-xs text-slate-400">Xavfsizlik holati</p>
              <p className="mt-2 text-2xl font-semibold text-emerald-400">
                Stable
              </p>
              <p className="mt-1 text-[11px] text-slate-400">
                Shubhali urinishlar aniqlanmadi
              </p>
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2 rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold">
                  So‘nggi login faoliyati
                </h3>
                <span className="text-[11px] text-slate-500">Demo data</span>
              </div>
              <div className="space-y-2 text-xs">
                <div className="flex items-center justify-between rounded-xl bg-slate-900 px-3 py-2">
                  <span className="text-slate-100">admin@example.com</span>
                  <span className="text-slate-500">Fingerprint · Tashkent</span>
                </div>
                <div className="flex items-center justify-between rounded-xl bg-slate-900 px-3 py-2">
                  <span className="text-slate-100">security@example.com</span>
                  <span className="text-slate-500">FaceID · iPhone</span>
                </div>
                <div className="flex items-center justify-between rounded-xl bg-slate-900 px-3 py-2">
                  <span className="text-slate-100">mobile@example.com</span>
                  <span className="text-slate-500">Windows Hello · Laptop</span>
                </div>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
              <h3 className="text-sm font-semibold">Tez sozlamalar</h3>
              <div className="space-y-2 text-xs">
                <label className="flex items-center justify-between rounded-xl bg-slate-900 px-3 py-2">
                  <span className="text-slate-100">
                    Faqat biometrik login ruxsat
                  </span>
                  <input type="checkbox" className="accent-primary-500" />
                </label>
                <label className="flex items-center justify-between rounded-xl bg-slate-900 px-3 py-2">
                  <span className="text-slate-100">
                    Yangi qurilma uchun tasdiq
                  </span>
                  <input type="checkbox" className="accent-primary-500" />
                </label>
                <label className="flex items-center justify-between rounded-xl bg-slate-900 px-3 py-2">
                  <span className="text-slate-100">
                    E-mail orqali xabarnoma
                  </span>
                  <input type="checkbox" className="accent-primary-500" />
                </label>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  )
}

export default App
