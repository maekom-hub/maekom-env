async function request(path, options = {}) {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: {
      ...(options.body && typeof options.body === 'string' && !options.rawContentType
        ? { 'Content-Type': 'application/json' }
        : {}),
      ...(options.headers || {}),
    },
    ...options,
  })

  if (res.status === 401 && !options.ignoreUnauthorized) {
    window.dispatchEvent(new CustomEvent('maekom:unauthorized'))
  }

  const contentType = res.headers.get('content-type') || ''
  const data = contentType.includes('application/json')
    ? await res.json().catch(() => ({}))
    : await res.text()

  if (!res.ok) {
    const message =
      (data && typeof data === 'object' && data.error) ||
      `Request failed (${res.status})`
    const err = new Error(message)
    err.status = res.status
    throw err
  }

  return data
}

export const api = {
  authStatus: () => request('/api/auth/status', { ignoreUnauthorized: true }),
  me: () => request('/api/auth/me', { ignoreUnauthorized: true }),
  login: (password, totpCode) =>
    request('/api/auth/login', {
      method: 'POST',
      ignoreUnauthorized: true,
      body: JSON.stringify({ password, totp_code: totpCode || '' }),
    }),
  logout: () => request('/api/auth/logout', { method: 'POST', ignoreUnauthorized: true }),

  listProjects: () => request('/api/projects'),
  createProject: (name, description) =>
    request('/api/projects', {
      method: 'POST',
      body: JSON.stringify({ name, description }),
    }),
  deleteProject: (projectID) =>
    request(`/api/projects/${projectID}`, { method: 'DELETE' }),

  listEnvironments: (projectID) =>
    request(`/api/projects/${projectID}/environments`),
  createEnvironment: (projectID, name) =>
    request(`/api/projects/${projectID}/environments`, {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),
  deleteEnvironment: (projectID, envID) =>
    request(`/api/projects/${projectID}/environments/${envID}`, { method: 'DELETE' }),

  listMaskedSecrets: (projectID, envID) =>
    request(`/api/projects/${projectID}/environments/${envID}/secrets?masked=true`),
  revealSecret: (projectID, envID, key) =>
    request(`/api/projects/${projectID}/environments/${envID}/secrets/${encodeURIComponent(key)}`),
  upsertSecret: (projectID, envID, payload) =>
    request(`/api/projects/${projectID}/environments/${envID}/secrets`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  deleteSecret: (projectID, envID, key) =>
    request(`/api/projects/${projectID}/environments/${envID}/secrets/${encodeURIComponent(key)}`, {
      method: 'DELETE',
    }),
  importDotEnv: (projectID, envID, content) =>
    request(`/api/projects/${projectID}/environments/${envID}/secrets/import`, {
      method: 'POST',
      rawContentType: true,
      headers: { 'Content-Type': 'text/plain' },
      body: content,
    }),
  exportDotEnv: (projectID, envID) =>
    request(`/api/projects/${projectID}/environments/${envID}/secrets/export`),

  listTokens: (projectID) => request(`/api/projects/${projectID}/tokens`),
  createToken: (projectID, payload) =>
    request(`/api/projects/${projectID}/tokens`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  deleteToken: (projectID, tokenID) =>
    request(`/api/projects/${projectID}/tokens/${tokenID}`, { method: 'DELETE' }),

  listWebhooks: (projectID) => request(`/api/projects/${projectID}/webhooks`),
  createWebhook: (projectID, payload) =>
    request(`/api/projects/${projectID}/webhooks`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  deleteWebhook: (projectID, webhookID) =>
    request(`/api/projects/${projectID}/webhooks/${webhookID}`, { method: 'DELETE' }),
  testWebhook: (projectID, webhookID) =>
    request(`/api/projects/${projectID}/webhooks/${webhookID}/test`, { method: 'POST' }),

  listAuditLogs: (limit = 100) => request(`/api/audit-logs?limit=${limit}`),
}
