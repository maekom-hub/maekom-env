import { useEffect, useState } from 'react'
import { Webhook, Plus, Trash2, Send, Eye, EyeOff } from 'lucide-react'
import { api } from '../api'

export default function WebhooksTab({ project, environments }) {
  const [webhooks, setWebhooks] = useState([])
  const [type, setType] = useState('discord')
  const [targetURL, setTargetURL] = useState('')
  const [secretKey, setSecretKey] = useState('')
  const [envID, setEnvID] = useState('')
  const [events, setEvents] = useState('*')
  const [revealedSecrets, setRevealedSecrets] = useState({})
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')

  async function loadWebhooks() {
    if (!project) return
    try {
      const res = await api.listWebhooks(project.id)
      setWebhooks(res.webhooks || [])
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => {
    loadWebhooks()
  }, [project?.id])

  async function handleCreate(e) {
    e.preventDefault()
    setError('')
    setNotice('')
    try {
      await api.createWebhook(project.id, {
        type,
        target_url: targetURL.trim(),
        secret_key: secretKey.trim(),
        env_id: envID || null,
        events: events.trim() || '*',
      })
      setTargetURL('')
      setSecretKey('')
      await loadWebhooks()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleTest(id) {
    setError('')
    setNotice('')
    try {
      await api.testWebhook(project.id, id)
      setNotice('Test webhook event delivered successfully.')
    } catch (err) {
      setError(`Test failed: ${err.message}`)
    }
  }

  async function handleDelete(id) {
    try {
      await api.deleteWebhook(project.id, id)
      await loadWebhooks()
    } catch (err) {
      setError(err.message)
    }
  }

  const envMap = Object.fromEntries((environments || []).map((e) => [e.id, e.name]))

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-white">
          Webhooks — <span className="text-emerald-400">{project.name}</span>
        </h2>
        <p className="text-xs text-slate-400">
          Receive secret rotation &amp; D-7/D-1 expiration alerts. Plaintext secret values are never included in payloads.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">
          {notice}
        </div>
      )}

      <form
        onSubmit={handleCreate}
        className="grid grid-cols-1 md:grid-cols-12 gap-3 rounded-xl border border-slate-800 bg-slate-900/60 p-4"
      >
        <select
          value={type}
          onChange={(e) => setType(e.target.value)}
          className="md:col-span-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-emerald-500 focus:outline-none"
        >
          <option value="discord">discord</option>
          <option value="slack">slack</option>
          <option value="email">email</option>
          <option value="custom">custom</option>
        </select>
        <input
          type="text"
          required
          value={targetURL}
          onChange={(e) => setTargetURL(e.target.value)}
          placeholder={type === 'email' ? 'ops@example.com' : 'https://...'}
          className="md:col-span-4 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
        />
        <input
          type="text"
          value={secretKey}
          onChange={(e) => setSecretKey(e.target.value)}
          placeholder="HMAC secret key (for custom)"
          className="md:col-span-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
        />
        <select
          value={envID}
          onChange={(e) => setEnvID(e.target.value)}
          className="md:col-span-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-emerald-500 focus:outline-none"
        >
          <option value="">All environments</option>
          {(environments || []).map((env) => (
            <option key={env.id} value={env.id}>
              {env.name}
            </option>
          ))}
        </select>
        <button
          type="submit"
          className="md:col-span-2 inline-flex items-center justify-center gap-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 px-3 py-2 text-sm font-medium text-white cursor-pointer"
        >
          <Plus className="h-4 w-4" /> Add
        </button>
      </form>

      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-800 bg-slate-900/80 text-xs uppercase text-slate-400">
            <tr>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Target</th>
              <th className="px-4 py-3">Env</th>
              <th className="px-4 py-3">HMAC Secret Key</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {webhooks.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                  No webhooks registered.
                </td>
              </tr>
            ) : (
              webhooks.map((wh) => {
                const shown = Boolean(revealedSecrets[wh.id])
                return (
                  <tr key={wh.id} className="hover:bg-slate-900/60">
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-800 px-2.5 py-0.5 text-xs font-medium text-slate-200">
                        <Webhook className="h-3 w-3 text-emerald-400" /> {wh.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-300 max-w-xs truncate">
                      {wh.target_url}
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      {wh.env_id ? envMap[wh.env_id] || wh.env_id : 'All'}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">
                      {wh.secret_key ? (
                        <span className="inline-flex items-center gap-1.5">
                          <span>{shown ? wh.secret_key : '••••••••'}</span>
                          <button
                            onClick={() =>
                              setRevealedSecrets((prev) => ({ ...prev, [wh.id]: !prev[wh.id] }))
                            }
                            className="p-1 text-slate-400 hover:text-white cursor-pointer"
                          >
                            {shown ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                          </button>
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="inline-flex items-center gap-1">
                        <button
                          onClick={() => handleTest(wh.id)}
                          className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-emerald-300 hover:bg-emerald-500/15 cursor-pointer"
                        >
                          <Send className="h-3.5 w-3.5" /> Test
                        </button>
                        <button
                          onClick={() => handleDelete(wh.id)}
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
    </div>
  )
}
