import { useEffect, useState } from 'react'
import { KeyRound, Plus, Trash2, Copy, Check, ShieldAlert } from 'lucide-react'
import { api } from '../api'

export default function TokensTab({ project, environments }) {
  const [tokens, setTokens] = useState([])
  const [name, setName] = useState('')
  const [scope, setScope] = useState('read')
  const [envID, setEnvID] = useState('')
  const [allowedIPs, setAllowedIPs] = useState('')
  const [createdToken, setCreatedToken] = useState('')
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')

  async function loadTokens() {
    if (!project) return
    try {
      const res = await api.listTokens(project.id)
      setTokens(res.tokens || [])
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => {
    setCreatedToken('')
    loadTokens()
  }, [project?.id])

  async function handleCreate(e) {
    e.preventDefault()
    setError('')
    setCreatedToken('')
    try {
      const res = await api.createToken(project.id, {
        name: name.trim(),
        scope,
        env_id: envID || null,
        allowed_ips: allowedIPs.trim(),
      })
      setCreatedToken(res.token)
      setName('')
      setAllowedIPs('')
      await loadTokens()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleRevoke(id) {
    try {
      await api.deleteToken(project.id, id)
      await loadTokens()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleCopyToken() {
    await navigator.clipboard.writeText(createdToken)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const envMap = Object.fromEntries((environments || []).map((e) => [e.id, e.name]))

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-white">
          Service Tokens — <span className="text-emerald-400">{project.name}</span>
        </h2>
        <p className="text-xs text-slate-400">
          Issue scoped tokens for CLI (<code>mkv</code>) or CI/CD runners. Plaintext tokens are shown only once.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}

      {createdToken && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 space-y-2">
          <div className="flex items-center gap-2 text-sm font-medium text-amber-300">
            <ShieldAlert className="h-4 w-4" />
            <span>Copy this token now — it will never be shown again:</span>
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 rounded-lg bg-slate-950 px-3 py-2 text-xs font-mono text-emerald-300 break-all border border-slate-800">
              {createdToken}
            </code>
            <button
              onClick={handleCopyToken}
              className="inline-flex items-center gap-1 rounded-lg bg-slate-800 hover:bg-slate-700 px-3 py-2 text-xs text-white cursor-pointer"
            >
              {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      )}

      <form
        onSubmit={handleCreate}
        className="grid grid-cols-1 md:grid-cols-12 gap-3 rounded-xl border border-slate-800 bg-slate-900/60 p-4"
      >
        <input
          type="text"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Token name (e.g. github-ci)"
          className="md:col-span-3 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
        />
        <select
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          className="md:col-span-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-emerald-500 focus:outline-none"
        >
          <option value="read">read</option>
          <option value="write">write</option>
        </select>
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
        <input
          type="text"
          value={allowedIPs}
          onChange={(e) => setAllowedIPs(e.target.value)}
          placeholder="Allowed IPs/CIDRs (optional)"
          className="md:col-span-3 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
        />
        <button
          type="submit"
          className="md:col-span-2 inline-flex items-center justify-center gap-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 px-3 py-2 text-sm font-medium text-white cursor-pointer"
        >
          <Plus className="h-4 w-4" /> Issue
        </button>
      </form>

      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-800 bg-slate-900/80 text-xs uppercase text-slate-400">
            <tr>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Scope</th>
              <th className="px-4 py-3">Environment</th>
              <th className="px-4 py-3">Allowed IPs</th>
              <th className="px-4 py-3 text-right">Revoke</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {tokens.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                  No service tokens issued for this project.
                </td>
              </tr>
            ) : (
              tokens.map((tok) => (
                <tr key={tok.id} className="hover:bg-slate-900/60">
                  <td className="px-4 py-3 font-medium text-slate-100 flex items-center gap-2">
                    <KeyRound className="h-4 w-4 text-slate-500" />
                    {tok.name}
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded-full border border-slate-700 bg-slate-800 px-2.5 py-0.5 text-xs font-mono text-slate-200">
                      {tok.scope}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    {tok.env_id ? envMap[tok.env_id] || tok.env_id : 'All'}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">
                    {tok.allowed_ips || 'Any'}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleRevoke(tok.id)}
                      className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-rose-400 hover:bg-rose-500/15 cursor-pointer"
                    >
                      <Trash2 className="h-3.5 w-3.5" /> Revoke
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
