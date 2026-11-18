import { useState } from 'react'
import { BookOpen, ChevronDown, ChevronRight, Copy, Check } from 'lucide-react'
import { useI18n } from '../i18n'

export default function QuickGuide({ items = [], commandLabel = '', command = '', defaultOpen = true }) {
  const { t } = useI18n()
  const [open, setOpen] = useState(defaultOpen)
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    if (!command) return
    await navigator.clipboard.writeText(command)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-2.5 text-xs font-medium text-slate-300 hover:bg-slate-800/50 transition cursor-pointer"
      >
        <span className="inline-flex items-center gap-2">
          <BookOpen className="h-3.5 w-3.5 text-emerald-400" />
          <span>{t('quickGuideTitle')}</span>
        </span>
        {open ? <ChevronDown className="h-4 w-4 text-slate-500" /> : <ChevronRight className="h-4 w-4 text-slate-500" />}
      </button>

      {open && (
        <div className="border-t border-slate-800/80 px-4 py-3 space-y-2.5 text-xs text-slate-400">
          <ul className="list-disc pl-4 space-y-1">
            {items.map((text, idx) => (
              <li key={idx} className="leading-relaxed">
                {text}
              </li>
            ))}
          </ul>

          {command && (
            <div className="pt-1 space-y-1">
              {commandLabel && <p className="text-[11px] text-slate-400">{commandLabel}</p>}
              <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">
                <code className="flex-1 min-w-0 font-mono text-[11px] text-emerald-300 overflow-x-auto whitespace-nowrap">
                  {command}
                </code>
                <button
                  type="button"
                  onClick={handleCopy}
                  className="shrink-0 inline-flex items-center gap-1 rounded-md bg-slate-800 hover:bg-slate-700 px-2 py-1 text-[11px] text-slate-200 cursor-pointer"
                >
                  {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  <span className="hidden sm:inline">{copied ? t('copied') : t('copy')}</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
