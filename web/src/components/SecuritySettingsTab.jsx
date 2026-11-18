import { useState } from 'react'
import { ShieldCheck, QrCode, Copy, Check, AlertTriangle, CheckCircle2 } from 'lucide-react'
import QRCode from 'qrcode'
import { api } from '../api'
import { useI18n } from '../i18n'
import QuickGuide from './QuickGuide'

export default function SecuritySettingsTab() {
  const { t } = useI18n()
  const [password, setPassword] = useState('')
  const [currentOTP, setCurrentOTP] = useState('')
  const [pendingSecret, setPendingSecret] = useState('')
  const [qrDataURL, setQrDataURL] = useState('')
  const [newOTP, setNewOTP] = useState('')
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleBeginReset(e) {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      const res = await api.settingsTOTPBegin(password, currentOTP)
      setPendingSecret(res.secret)
      const dataUrl = await QRCode.toDataURL(res.otpauth_uri, {
        width: 200,
        margin: 2,
        color: { dark: '#0f172a', light: '#ffffff' },
      })
      setQrDataURL(dataUrl)
      setPassword('')
      setCurrentOTP('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleConfirmReset(e) {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      await api.settingsTOTPConfirm(newOTP)
      setPendingSecret('')
      setQrDataURL('')
      setNewOTP('')
      setSuccess(t('otpResetSuccess'))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  function handleCancel() {
    setPendingSecret('')
    setQrDataURL('')
    setNewOTP('')
    setError('')
  }

  async function handleCopy() {
    await navigator.clipboard.writeText(pendingSecret)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="max-w-xl space-y-5">
      <div className="flex items-start gap-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <h2 className="text-base sm:text-lg font-semibold text-white">{t('securityTitle')}</h2>
          <p className="text-xs text-slate-400 mt-0.5">{t('securityDesc')}</p>
        </div>
      </div>

      <QuickGuide items={[t('securityGuide1'), t('securityGuide2')]} />

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {success && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          <span>{success}</span>
        </div>
      )}

      {!pendingSecret ? (
        <form
          onSubmit={handleBeginReset}
          className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5"
        >
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">
              {t('reverifyPassword')}
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t('enterAdminPassword')}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">
              {t('reverifyOTP')}
            </label>
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={currentOTP}
              onChange={(e) => setCurrentOTP(e.target.value.replace(/\D/g, ''))}
              placeholder="000000"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono tracking-widest text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
            />
          </div>

          <button
            type="submit"
            disabled={loading || (!password && currentOTP.length !== 6)}
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-4 py-2 text-sm font-medium text-white cursor-pointer"
          >
            <QrCode className="h-4 w-4" />
            {t('startOTPReset')}
          </button>
        </form>
      ) : (
        <form
          onSubmit={handleConfirmReset}
          className="space-y-4 rounded-xl border border-amber-500/30 bg-slate-900/70 p-5"
        >
          <div>
            <h3 className="text-base font-semibold text-white">{t('confirmOTPResetTitle')}</h3>
            <p className="text-xs text-slate-400 mt-1">{t('confirmOTPResetDesc')}</p>
          </div>

          {qrDataURL && (
            <div className="flex justify-center py-2">
              <img
                src={qrDataURL}
                alt="New Google OTP QR Code"
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
                {pendingSecret}
              </code>
              <button
                type="button"
                onClick={handleCopy}
                className="rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 p-2 text-slate-200 cursor-pointer"
              >
                {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
              </button>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">
              {t('totpCodeLabel')}
            </label>
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              required
              autoFocus
              value={newOTP}
              onChange={(e) => setNewOTP(e.target.value.replace(/\D/g, ''))}
              placeholder="000000"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-center text-lg tracking-widest font-mono text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
            />
          </div>

          <div className="flex gap-2">
            <button
              type="button"
              onClick={handleCancel}
              className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800 cursor-pointer"
            >
              {t('cancel')}
            </button>
            <button
              type="submit"
              disabled={loading || newOTP.length !== 6}
              className="flex-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-4 py-2 text-sm font-medium text-white cursor-pointer"
            >
              {loading ? t('verifying') : t('confirmResetBtn')}
            </button>
          </div>
        </form>
      )}
    </div>
  )
}
