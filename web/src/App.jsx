import { useEffect, useState } from 'react'
import {
  ShieldCheck,
  KeyRound,
  Webhook,
  History,
  Lock,
  Plus,
  LogOut,
  FolderGit2,
  Layers,
  Settings,
  Menu,
  X,
} from 'lucide-react'
import { api } from './api'
import { I18nProvider, LangSwitch, useI18n } from './i18n'
import LoginView from './components/LoginView'
import SecretsTab from './components/SecretsTab'
import TokensTab from './components/TokensTab'
import WebhooksTab from './components/WebhooksTab'
import AuditLogsTab from './components/AuditLogsTab'
import SecuritySettingsTab from './components/SecuritySettingsTab'

const DEFAULT_ENVS = ['local', 'dev', 'staging', 'prod']

function Dashboard() {
  const { t } = useI18n()
  const [authState, setAuthState] = useState('checking')
  const [projects, setProjects] = useState([])
  const [selectedProject, setSelectedProject] = useState(null)
  const [environments, setEnvironments] = useState([])
  const [selectedEnv, setSelectedEnv] = useState(null)
  const [activeTab, setActiveTab] = useState('secrets')
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const [newProjectName, setNewProjectName] = useState('')
  const [newEnvName, setNewEnvName] = useState('')
  const [sidebarError, setSidebarError] = useState('')

  async function checkAuth() {
    try {
      const me = await api.me()
      if (me && me.is_admin) {
        setAuthState('authenticated')
        return
      }
      setAuthState('unauthenticated')
    } catch {
      setAuthState('unauthenticated')
    }
  }

  useEffect(() => {
    checkAuth()
    const onUnauthorized = () => {
      setAuthState('unauthenticated')
      setProjects([])
      setSelectedProject(null)
      setEnvironments([])
      setSelectedEnv(null)
    }
    window.addEventListener('maekom:unauthorized', onUnauthorized)
    return () => window.removeEventListener('maekom:unauthorized', onUnauthorized)
  }, [])

  async function loadProjects() {
    try {
      const res = await api.listProjects()
      const list = res.projects || []
      setProjects(list)
      if (list.length > 0) {
        setSelectedProject((prev) => list.find((p) => p.id === prev?.id) || list[0])
      } else {
        setSelectedProject(null)
      }
    } catch (err) {
      setSidebarError(err.message)
    }
  }

  async function loadEnvironments(projectID) {
    if (!projectID) {
      setEnvironments([])
      setSelectedEnv(null)
      return
    }
    try {
      const res = await api.listEnvironments(projectID)
      const list = res.environments || []
      setEnvironments(list)
      if (list.length > 0) {
        setSelectedEnv((prev) => list.find((e) => e.id === prev?.id) || list[0])
      } else {
        setSelectedEnv(null)
      }
    } catch (err) {
      setSidebarError(err.message)
    }
  }

  useEffect(() => {
    if (authState === 'authenticated') {
      loadProjects()
    }
  }, [authState])

  useEffect(() => {
    if (authState === 'authenticated' && selectedProject?.id) {
      loadEnvironments(selectedProject.id)
    }
  }, [authState, selectedProject?.id])

  async function handleCreateProject(e) {
    e.preventDefault()
    if (!newProjectName.trim()) return
    setSidebarError('')
    try {
      const proj = await api.createProject(newProjectName.trim(), '')
      setNewProjectName('')
      await loadProjects()
      setSelectedProject(proj)
    } catch (err) {
      setSidebarError(err.message)
    }
  }

  async function handleCreateEnv(name) {
    if (!selectedProject || !name.trim()) return
    setSidebarError('')
    try {
      const env = await api.createEnvironment(selectedProject.id, name.trim())
      setNewEnvName('')
      await loadEnvironments(selectedProject.id)
      setSelectedEnv(env)
    } catch (err) {
      setSidebarError(err.message)
    }
  }

  async function handleLogout() {
    await api.logout().catch(() => {})
    setAuthState('unauthenticated')
    setProjects([])
    setSelectedProject(null)
    setEnvironments([])
    setSelectedEnv(null)
  }

  if (authState === 'checking') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-400 text-sm">
        {t('verifyingSession')}
      </div>
    )
  }

  if (authState !== 'authenticated') {
    return <LoginView onSuccess={() => setAuthState('authenticated')} />
  }

  const tabs = [
    { id: 'secrets', label: t('tabSecrets'), icon: Lock },
    { id: 'tokens', label: t('tabTokens'), icon: KeyRound },
    { id: 'webhooks', label: t('tabWebhooks'), icon: Webhook },
    { id: 'audit', label: t('tabAudit'), icon: History },
    { id: 'security', label: t('tabSecurity'), icon: Settings },
  ]

  const sidebarContent = (
    <>
      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        <p className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-[11px] leading-relaxed text-slate-400">
          {t('sidebarGuide')}
        </p>

        {sidebarError && (
          <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
            {sidebarError}
          </div>
        )}

        {/* Projects */}
        <div>
          <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
            <FolderGit2 className="h-3.5 w-3.5" /> {t('projects')}
          </div>
          <div className="space-y-1 mb-2">
            {projects.map((p) => (
              <button
                key={p.id}
                onClick={() => {
                  setSelectedProject(p)
                  setMobileMenuOpen(false)
                }}
                className={`w-full text-left rounded-lg px-3 py-2 text-sm transition cursor-pointer ${
                  selectedProject?.id === p.id
                    ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-medium'
                    : 'text-slate-300 hover:bg-slate-800/70'
                }`}
              >
                {p.name}
              </button>
            ))}
            {projects.length === 0 && (
              <p className="text-xs text-slate-500 px-1 py-1">{t('createFirstProject')}</p>
            )}
          </div>
          <form onSubmit={handleCreateProject} className="flex gap-1.5">
            <input
              type="text"
              value={newProjectName}
              onChange={(e) => setNewProjectName(e.target.value)}
              placeholder={t('newProjectPlaceholder')}
              className="flex-1 min-w-0 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
            />
            <button
              type="submit"
              className="rounded-lg bg-slate-800 hover:bg-slate-700 px-2.5 py-1.5 text-slate-200 cursor-pointer"
            >
              <Plus className="h-4 w-4" />
            </button>
          </form>
        </div>

        {/* Environments */}
        {selectedProject && (
          <div>
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              <Layers className="h-3.5 w-3.5" /> {t('environments')}
            </div>
            <div className="space-y-1 mb-2">
              {environments.map((env) => (
                <button
                  key={env.id}
                  onClick={() => {
                    setSelectedEnv(env)
                    setMobileMenuOpen(false)
                  }}
                  className={`w-full text-left rounded-lg px-3 py-1.5 text-sm transition cursor-pointer ${
                    selectedEnv?.id === env.id
                      ? 'bg-slate-800 text-white font-medium border border-slate-700'
                      : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                  }`}
                >
                  {env.name}
                </button>
              ))}
            </div>
            <div className="flex flex-wrap gap-1 mb-2">
              {DEFAULT_ENVS.filter(
                (name) => !environments.some((e) => e.name.toLowerCase() === name)
              ).map((name) => (
                <button
                  key={name}
                  onClick={() => handleCreateEnv(name)}
                  className="rounded-md border border-dashed border-slate-700 hover:border-emerald-500/50 px-2 py-0.5 text-xs text-slate-400 hover:text-emerald-300 cursor-pointer"
                >
                  + {name}
                </button>
              ))}
            </div>
            <form
              onSubmit={(e) => {
                e.preventDefault()
                handleCreateEnv(newEnvName)
              }}
              className="flex gap-1.5"
            >
              <input
                type="text"
                value={newEnvName}
                onChange={(e) => setNewEnvName(e.target.value)}
                placeholder={t('customEnvPlaceholder')}
                className="flex-1 min-w-0 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
              <button
                type="submit"
                className="rounded-lg bg-slate-800 hover:bg-slate-700 px-2.5 py-1.5 text-slate-200 cursor-pointer"
              >
                <Plus className="h-4 w-4" />
              </button>
            </form>
          </div>
        )}
      </div>
    </>
  )

  return (
    <div className="min-h-screen flex flex-col lg:flex-row bg-slate-950 text-slate-100">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex lg:w-72 shrink-0 border-r border-slate-800 bg-slate-900/50 flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="h-6 w-6 text-emerald-400" />
            <span className="font-semibold text-white tracking-tight">maekom-env</span>
          </div>
          <button
            onClick={handleLogout}
            title={t('signOut')}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white cursor-pointer"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
        {sidebarContent}
      </aside>

      {/* Mobile Slide-Over Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-40 flex lg:hidden">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setMobileMenuOpen(false)}
          />
          <aside className="relative z-50 w-72 max-w-[85vw] bg-slate-900 border-r border-slate-800 flex flex-col h-full">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-emerald-400" />
                <span className="font-semibold text-white text-sm">{t('menuProjects')}</span>
              </div>
              <button
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-md p-1 text-slate-400 hover:text-white cursor-pointer"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            {sidebarContent}
          </aside>
        </div>
      )}

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0">
        {/* Mobile Top Bar */}
        <div className="flex lg:hidden items-center justify-between gap-2 px-3 py-2.5 border-b border-slate-800 bg-slate-900/70">
          <div className="flex items-center gap-2 min-w-0">
            <button
              onClick={() => setMobileMenuOpen(true)}
              className="rounded-lg border border-slate-700 bg-slate-800 p-1.5 text-slate-200 cursor-pointer"
              aria-label={t('menuProjects')}
            >
              <Menu className="h-5 w-5" />
            </button>
            <div className="min-w-0">
              <div className="text-sm font-semibold text-white truncate">maekom-env</div>
              {selectedProject && (
                <div className="text-[11px] text-emerald-400 truncate">
                  {selectedProject.name}
                  {selectedEnv ? ` / ${selectedEnv.name}` : ''}
                </div>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <LangSwitch />
            <button
              onClick={handleLogout}
              title={t('signOut')}
              className="rounded-lg border border-slate-700 bg-slate-800 p-1.5 text-slate-300 hover:text-white cursor-pointer"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <header className="border-b border-slate-800 px-3 sm:px-6 py-2.5 sm:py-3 flex items-center justify-between gap-2 bg-slate-900/30">
          <div className="flex flex-wrap items-center gap-1.5 sm:gap-2">
            {tabs.map((tab) => {
              const Icon = tab.icon
              const active = activeTab === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 sm:px-3.5 sm:py-2 text-xs sm:text-sm font-medium whitespace-nowrap transition cursor-pointer ${
                    active
                      ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                      : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                  }`}
                >
                  <Icon className="h-3.5 w-3.5 sm:h-4 sm:w-4" />
                  <span>{tab.label}</span>
                </button>
              )
            })}
          </div>
          <div className="hidden lg:block shrink-0">
            <LangSwitch />
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-3 sm:p-6">
          {activeTab === 'audit' ? (
            <AuditLogsTab />
          ) : activeTab === 'security' ? (
            <SecuritySettingsTab />
          ) : !selectedProject ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 sm:p-10 text-center text-sm text-slate-400">
              {t('selectProjectPrompt')}
            </div>
          ) : activeTab === 'secrets' ? (
            selectedEnv ? (
              <SecretsTab project={selectedProject} environment={selectedEnv} />
            ) : (
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 sm:p-10 text-center text-sm text-slate-400">
                {t('selectEnvPrompt')}
              </div>
            )
          ) : activeTab === 'tokens' ? (
            <TokensTab project={selectedProject} environments={environments} />
          ) : (
            <WebhooksTab project={selectedProject} environments={environments} />
          )}
        </div>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <I18nProvider>
      <Dashboard />
    </I18nProvider>
  )
}
