import { useEffect, useRef, useState } from 'react'
import {
  Eye,
  EyeOff,
  Copy,
  Check,
  Trash2,
  Plus,
  Upload,
  Download,
  Clock,
  X,
} from 'lucide-react'
import { api } from '../api'

function formatDDayBadge(expiresAt) {
  if (!expiresAt) return null
  const diffMs = new Date(expiresAt).getTime() - Date.now()
  const days = Math.ceil(diffMs / (1000 * 60 * 60 * 24))
  if (days <= 0) {
    return { label: 'Expired', cls: 'bg-rose-500/20 text-rose-300 border-rose-500/40' }
  }
  if (days <= 1) {
    return { label: `D-${days}`, cls: 'bg-rose-500/20 text-rose-300 border-rose-500/40' }
  }
  if (days <= 7) {
    return { label: `D-${days}`, cls: 'bg-amber-500/20 text-amber-300 border-amber-500/40' }
  }
  return { label: `D-${days}`, cls: 'bg-slate-800 text-slate-300 border-slate-700' }
}

export default function SecretsTab({ project, environment }) {
  const [secrets, setSecrets] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // Map of key -> { value, expiresInSec }
  const [revealed, setRevealed] = useState({})
  const revealTimersRef = useRef({})

  // Clipboard auto-clear state (30s)
  const [copiedKey, setCopiedKey] = useState('')
  const [clipboardSec, setClipboardSec] = useState(0)
  const clipboardTimerRef = useRef(null)

  // Add/Edit form
  const [newKey, setNewKey] = useState('')
  const [newValue, setNewValue] = useState('')
  const [newExpires, setNewExpires] = useState('')

  // Import modal
  const [showImport, setShowImport] = useState(false)
  const [importText, setImportText] = useState('')

  async function loadSecrets() {
    if (!project || !environment) return
    setLoading(true)
    setError('')
    try {
      const res = await api.listMaskedSecrets(project.id, environment.id)
      setSecrets(res.secrets || [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    clearAllRevealTimers()
    setRevealed({})
    loadSecrets()
    return () => clearAllRevealTimers()
  }, [project?.id, environment?.id])

  useEffect(() => {
    return () => {
      if (clipboardTimerRef.current) clearInterval(clipboardTimerRef.current)
    }
  }, [])

  function clearAllRevealTimers() {
    Object.values(revealTimersRef.current).forEach((t) => clearInterval(t))
    revealTimersRef.current = {}
  }

  function maskKey(key) {
    if (revealTimersRef.current[key]) {
      clearInterval(revealTimersRef.current[key])
      delete revealTimersRef.current[key]
    }
    setRevealed((prev) => {
      const next = { ...prev }
      delete next[key]
      return next
    })
  }

  async function handleToggleReveal(key) {
    if (revealed[key]) {
      maskKey(key)
      return
    }
    try {
      const res = await api.revealSecret(project.id, environment.id, key)
      setRevealed((prev) => ({
        ...prev,
        [key]: { value: res.value, sec: 10 },
      }))

      if (revealTimersRef.current[key]) clearInterval(revealTimersRef.current[key])
      revealTimersRef.current[key] = setInterval(() => {
        setRevealed((prev) => {
          const item = prev[key]
          if (!item) return prev
          if (item.sec <= 1) {
            clearInterval(revealTimersRef.current[key])
            delete revealTimersRef.current[key]
            const next = { ...prev }
            delete next[key]
            return next
          }
          return { ...prev, [key]: { ...item, sec: item.sec - 1 } }
        })
      }, 1000)
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleCopy(key) {
    try {
      let val = revealed[key]?.value
      if (val === undefined) {
        const res = await api.revealSecret(project.id, environment.id, key)
        val = res.value
      }
      await navigator.clipboard.writeText(val)
      setCopiedKey(key)
      setClipboardSec(30)

      if (clipboardTimerRef.current) clearInterval(clipboardTimerRef.current)
      clipboardTimerRef.current = setInterval(() => {
        setClipboardSec((prev) => {
          if (prev <= 1) {
            clearInterval(clipboardTimerRef.current)
            clipboardTimerRef.current = null
            navigator.clipboard.writeText('').catch(() => {})
            setCopiedKey('')
            return 0
          }
          return prev - 1
        })
      }, 1000)
    } catch (err) {
      setError(err.message || 'Clipboard copy failed')
    }
  }

  async function handleSaveSecret(e) {
    e.preventDefault()
    if (!newKey.trim()) return
    setError('')
    try {
      const payload = {
        key: newKey.trim(),
        value: newValue,
        ...(newExpires ? { expires_at: new Date(newExpires).toISOString() } : {}),
      }
      await api.upsertSecret(project.id, environment.id, payload)
      setNewKey('')
      setNewValue('')
      setNewExpires('')
      await loadSecrets()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleDelete(key) {
    try {
      await api.deleteSecret(project.id, environment.id, key)
      maskKey(key)
      await loadSecrets()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleImport(e) {
    e.preventDefault()
    setError('')
    try {
      await api.importDotEnv(project.id, environment.id, importText)
      setImportText('')
      setShowImport(false)
      await loadSecrets()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleExport() {
    try {
      const text = await api.exportDotEnv(project.id, environment.id)
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${environment.name}.env`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">
            Secrets — <span className="text-emerald-400">{project.name}</span> / {environment.name}
          </h2>
          <p className="text-xs text-slate-400">
            Values stay masked by default. Revealed values auto-mask after 10s; clipboard clears after 30s.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {clipboardSec > 0 && (
            <span className="rounded-full border border-emerald-500/40 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-300">
              Clipboard clears in {clipboardSec}s
            </span>
          )}
          <button
            onClick={() => setShowImport(true)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 cursor-pointer"
          >
            <Upload className="h-3.5 w-3.5" /> Import .env
          </button>
          <button
            onClick={handleExport}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 cursor-pointer"
          >
            <Download className="h-3.5 w-3.5" /> Export .env
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}

      <form
        onSubmit={handleSaveSecret}
        className="grid grid-cols-1 md:grid-cols-12 gap-3 rounded-xl border border-slate-800 bg-slate-900/60 p-4"
      >
        <input
          type="text"
          required
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
          placeholder="KEY_NAME"
          className="md:col-span-3 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
        />
        <input
          type="password"
          required
          value={newValue}
          onChange={(e) => setNewValue(e.target.value)}
          placeholder="Secret value"
          className="md:col-span-5 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
        />
        <input
          type="date"
          value={newExpires}
          onChange={(e) => setNewExpires(e.target.value)}
          title="Optional expiration date"
          className="md:col-span-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-300 focus:border-emerald-500 focus:outline-none"
        />
        <button
          type="submit"
          className="md:col-span-2 inline-flex items-center justify-center gap-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 px-3 py-2 text-sm font-medium text-white cursor-pointer"
        >
          <Plus className="h-4 w-4" /> Save
        </button>
      </form>

      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-800 bg-slate-900/80 text-xs uppercase text-slate-400">
            <tr>
              <th className="px-4 py-3">Key</th>
              <th className="px-4 py-3">Value</th>
              <th className="px-4 py-3">Expiration</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {loading ? (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center text-slate-400">
                  Loading secrets...
                </td>
              </tr>
            ) : secrets.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center text-slate-500">
                  No secrets in this environment yet.
                </td>
              </tr>
            ) : (
              secrets.map((sec) => {
                const rev = revealed[sec.key]
                const badge = formatDDayBadge(sec.expires_at)
                return (
                  <tr key={sec.id} className="hover:bg-slate-900/60">
                    <td className="px-4 py-3 font-mono font-medium text-slate-100">{sec.key}</td>
                    <td className="px-4 py-3 font-mono text-slate-300">
                      {rev ? (
                        <span className="inline-flex items-center gap-2">
                          <span className="text-emerald-300 break-all">{rev.value}</span>
                          <span className="text-xs text-slate-500">({rev.sec}s)</span>
                        </span>
                      ) : (
                        <span className="tracking-widest text-slate-500">••••••••</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {badge ? (
                        <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${badge.cls}`}>
                          <Clock className="h-3 w-3" /> {badge.label}
                        </span>
                      ) : (
                        <span className="text-xs text-slate-500">Never</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="inline-flex items-center gap-1">
                        <button
                          onClick={() => handleToggleReveal(sec.key)}
                          title={rev ? 'Mask' : 'Reveal for 10s'}
                          className="rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white cursor-pointer"
                        >
                          {rev ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </button>
                        <button
                          onClick={() => handleCopy(sec.key)}
                          title="Copy (auto-clears in 30s)"
                          className="rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white cursor-pointer"
                        >
                          {copiedKey === sec.key ? (
                            <Check className="h-4 w-4 text-emerald-400" />
                          ) : (
                            <Copy className="h-4 w-4" />
                          )}
                        </button>
                        <button
                          onClick={() => handleDelete(sec.key)}
                          title="Delete secret"
                          className="rounded-md p-1.5 text-slate-400 hover:bg-rose-500/20 hover:text-rose-400 cursor-pointer"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {showImport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-lg rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-semibold text-white">Import .env</h3>
              <button
                onClick={() => setShowImport(false)}
                className="rounded-md p-1 text-slate-400 hover:text-white cursor-pointer"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <form onSubmit={handleImport} className="space-y-4">
              <textarea
                rows={10}
                required
                value={importText}
                onChange={(e) => setImportText(e.target.value)}
                placeholder={"DATABASE_URL=postgres://...\nAPI_KEY=sk_live_..."}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowImport(false)}
                  className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="rounded-lg bg-emerald-600 hover:bg-emerald-500 px-4 py-2 text-sm font-medium text-white cursor-pointer"
                >
                  Import Secrets
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
