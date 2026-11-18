import { useEffect, useState } from 'react'
import { RefreshCw, CheckCircle2, XCircle } from 'lucide-react'
import { api } from '../api'

export default function AuditLogsTab() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function loadLogs() {
    setLoading(true)
    setError('')
    try {
      const res = await api.listAuditLogs(100)
      setLogs(res.audit_logs || [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadLogs()
  }, [])

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-white">Audit Logs</h2>
          <p className="text-xs text-slate-400">
            Authentication attempts (success/failure IPs) and secret view/change history.
          </p>
        </div>
        <button
          onClick={loadLogs}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 px-3 py-1.5 text-xs text-slate-200 cursor-pointer"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-800 bg-slate-900/80 text-xs uppercase text-slate-400">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Event</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3">IP Address</th>
              <th className="px-4 py-3">Target / Detail</th>
              <th className="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {logs.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                  No audit events recorded yet.
                </td>
              </tr>
            ) : (
              logs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-900/60">
                  <td className="px-4 py-2.5 text-xs text-slate-400 whitespace-nowrap">
                    {new Date(log.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-slate-200">{log.event}</td>
                  <td className="px-4 py-2.5 text-xs text-slate-300">{log.actor}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-slate-400">{log.ip_address || '—'}</td>
                  <td className="px-4 py-2.5 text-xs text-slate-300">
                    {log.target_key ? <code className="text-emerald-300 mr-2">{log.target_key}</code> : null}
                    <span className="text-slate-400">{log.detail}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    {log.success ? (
                      <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                        <CheckCircle2 className="h-3.5 w-3.5" /> OK
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-xs text-rose-400">
                        <XCircle className="h-3.5 w-3.5" /> Fail
                      </span>
                    )}
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
