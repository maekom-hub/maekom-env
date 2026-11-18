import { useEffect, useState } from 'react'
import { Lock, ShieldCheck, AlertTriangle, QrCode, ArrowLeft, Copy, Check } from 'lucide-react'
import QRCode from 'qrcode'
import { api } from '../api'
import { LangSwitch, useI18n } from '../i18n'

export default function LoginView({ onSuccess }) {
  const { t } = useI18n()
  const [step, setStep] = useState('password') // 'password' | 'setup' | 'verify'
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [tempToken, setTempToken] = useState('')
  const [setupSecret, setSetupSecret] = useState('')
  const [qrDataURL, setQrDataURL] = useState('')
  const [copiedSecret, setCopiedSecret] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    api.authStatus().catch(() => {})
  }, [])

  async function handlePasswordSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await api.login(password, '')
      setPassword('')
      if (res.status === 'totp_setup_required') {
        setTempToken(res.temp_token)
        setSetupSecret(res.secret)
        const dataUrl = await QRCode.toDataURL(res.otpauth_uri, {
          width: 200,
          margin: 2,
          color: { dark: '#0f172a', light: '#ffffff' },
        })
        setQrDataURL(dataUrl)
        setStep('setup')
        return
      }
      if (res.status === 'totp_verify_required') {
        setTempToken(res.temp_token)
        setStep('verify')
        return
      }
      onSuccess()
    } catch (err) {
      setError(err.message || 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  async function handleTOTPSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (step === 'setup') {
        await api.totpSetup(tempToken, totpCode)
      } else {
        await api.totpVerify(tempToken, totpCode)
      }
      setTotpCode('')
      setTempToken('')
      setSetupSecret('')
      setQrDataURL('')
      onSuccess()
    } catch (err) {
      setError(err.message || 'Invalid OTP code')
    } finally {
      setLoading(false)
    }
  }

  function handleResetToLogin() {
    setStep('password')
    setTotpCode('')
    setTempToken('')
    setSetupSecret('')
    setQrDataURL('')
    setError('')
  }

  async function handleCopySecret() {
    await navigator.clipboard.writeText(setupSecret)
    setCopiedSecret(true)
    setTimeout(() => setCopiedSecret(false), 2000)
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-slate-950 px-4 py-8">
      <div className="w-full max-w-md flex justify-end mb-3">
        <LangSwitch />
      </div>

      <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/80 p-8 shadow-2xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            {step === 'password' ? <ShieldCheck className="h-6 w-6" /> : <QrCode className="h-6 w-6" />}
          </div>
          <div>
            <h1 className="text-xl font-semibold text-white">maekom-env</h1>
            <p className="text-xs text-slate-400">{t('appSubtitle')}</p>
          </div>
        </div>

        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2.5 text-sm text-rose-300">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {step === 'password' && (
          <form onSubmit={handlePasswordSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium uppercase tracking-wider text-slate-400 mb-1.5">
                {t('adminPassword')}
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type="password"
                  required
                  autoFocus
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t('enterAdminPassword')}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 py-2.5 text-sm font-medium text-white transition cursor-pointer"
            >
              {loading ? t('signingIn') : t('signIn')}
            </button>
          </form>
        )}

        {step === 'setup' && (
          <form onSubmit={handleTOTPSubmit} className="space-y-4">
            <div>
              <h2 className="text-base font-semibold text-white">{t('totpSetupTitle')}</h2>
              <p className="mt-1 text-xs text-slate-400">{t('totpSetupDesc')}</p>
            </div>

            {qrDataURL && (
              <div className="flex justify-center py-2">
                <img
                  src={qrDataURL}
                  alt="Google OTP QR Code"
                  className="rounded-xl border border-slate-700 bg-white p-2"
                />
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                {t('totpManualSecret')}
              </label>
              <div className="flex items-center gap-2">
                <code className="flex-1 rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs font-mono text-emerald-300 break-all">
                  {setupSecret}
                </code>
                <button
                  type="button"
                  onClick={handleCopySecret}
                  className="rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 p-2 text-slate-200 cursor-pointer"
                >
                  {copiedSecret ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium uppercase tracking-wider text-slate-400 mb-1.5">
                {t('totpCodeLabel')}
              </label>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                required
                autoFocus
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000000"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-center text-lg tracking-widest font-mono text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div className="flex gap-2">
              <button
                type="button"
                onClick={handleResetToLogin}
                className="inline-flex items-center justify-center gap-1 rounded-lg border border-slate-700 px-3 py-2.5 text-sm text-slate-300 hover:bg-slate-800 cursor-pointer"
              >
                <ArrowLeft className="h-4 w-4" /> {t('backToLogin')}
              </button>
              <button
                type="submit"
                disabled={loading || totpCode.length !== 6}
                className="flex-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 py-2.5 text-sm font-medium text-white transition cursor-pointer"
              >
                {loading ? t('verifying') : t('verifyAndContinue')}
              </button>
            </div>
          </form>
        )}

        {step === 'verify' && (
          <form onSubmit={handleTOTPSubmit} className="space-y-4">
            <div>
              <h2 className="text-base font-semibold text-white">{t('totpVerifyTitle')}</h2>
              <p className="mt-1 text-xs text-slate-400">{t('totpVerifyDesc')}</p>
            </div>

            <div>
              <label className="block text-xs font-medium uppercase tracking-wider text-slate-400 mb-1.5">
                {t('totpCodeLabel')}
              </label>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                required
                autoFocus
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000000"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-center text-lg tracking-widest font-mono text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div className="flex gap-2">
              <button
                type="button"
                onClick={handleResetToLogin}
                className="inline-flex items-center justify-center gap-1 rounded-lg border border-slate-700 px-3 py-2.5 text-sm text-slate-300 hover:bg-slate-800 cursor-pointer"
              >
                <ArrowLeft className="h-4 w-4" /> {t('backToLogin')}
              </button>
              <button
                type="submit"
                disabled={loading || totpCode.length !== 6}
                className="flex-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 py-2.5 text-sm font-medium text-white transition cursor-pointer"
              >
                {loading ? t('verifying') : t('verifyAndContinue')}
              </button>
            </div>
          </form>
        )}

        <p className="mt-5 text-center text-xs text-slate-500">{t('loginFooter')}</p>
      </div>
    </div>
  )
}
