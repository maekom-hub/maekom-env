import { createContext, useContext, useState } from 'react'

const STORAGE_KEY = 'maekom_lang'

export function getInitialLang() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved === 'ko' || saved === 'en') return saved
  } catch {
    // ignore storage errors
  }
  if (typeof navigator !== 'undefined' && navigator.language) {
    if (navigator.language.toLowerCase().startsWith('en')) {
      return 'en'
    }
  }
  return 'ko'
}

export const translations = {
  ko: {
    appSubtitle: '암호화 .env 시크릿 매니저',
    verifyingSession: '세션 확인 중...',
    adminPassword: '관리자 비밀번호',
    enterAdminPassword: 'ADMIN_PASSWORD 입력',
    signIn: '로그인',
    signingIn: '로그인 중...',
    loginFooter: 'HttpOnly Strict 세션 쿠키 및 무차별 대입 방어 적용됨',
    totpSetupTitle: 'Google OTP (2FA) 최초 등록',
    totpSetupDesc: 'Google Authenticator 또는 호환 OTP 앱으로 아래 QR 코드를 스캔한 뒤 6자리 코드를 입력하세요.',
    totpManualSecret: '수동 입력용 시크릿 키',
    totpCodeLabel: '6자리 OTP 코드',
    totpVerifyTitle: '2단계 인증 (Google OTP)',
    totpVerifyDesc: '인증 앱에 표시된 6자리 OTP 코드를 입력하세요.',
    verifyAndContinue: '인증 및 로그인',
    verifying: '확인 중...',
    backToLogin: '다시 로그인',
    projects: '프로젝트',
    newProjectPlaceholder: '새 프로젝트...',
    createFirstProject: '아래에서 첫 프로젝트를 생성하세요.',
    environments: '환경 (Environments)',
    customEnvPlaceholder: '직접 입력...',
    signOut: '로그아웃',
    selectProjectPrompt: '사이드바에서 프로젝트를 선택하거나 새로 생성하세요.',
    selectEnvPrompt: '사이드바에서 환경(local, dev, staging, prod 등)을 선택하거나 생성하세요.',
    tabSecrets: 'Secrets',
    tabTokens: 'Service Tokens',
    tabWebhooks: 'Webhooks',
    tabAudit: 'Audit Logs',
    tabSecurity: '보안 / OTP 설정',
    secretsDesc: '목록에서는 기본적으로 마스킹되며, 보기(10초 자동 숨김) 또는 복사(30초 클립보드 자동 비우기) 시에만 복호화됩니다.',
    clipboardClearsIn: '클립보드 자동 비우기: {sec}초',
    importEnv: '.env 가져오기',
    exportEnv: '.env 내보내기',
    keyPlaceholder: 'KEY_NAME (영문/_/숫자)',
    valuePlaceholder: '시크릿 값 (입력 중 평문 표시 · 한글/특수문자/멀티라인 지원)',
    uppercaseBtn: '대문자',
    saveSecret: '저장',
    updateSecret: '수정 저장',
    cancelEdit: '취소',
    invalidKeyError: "Key는 영문자 또는 '_'로 시작해야 하며 영문자, 숫자, '_'만 사용할 수 있습니다.",
    colKey: 'Key',
    colValue: 'Value',
    colExpiration: '만료일',
    colActions: '작업',
    loadingSecrets: '시크릿 불러오는 중...',
    noSecrets: '이 환경에 등록된 시크릿이 없습니다.',
    neverExpires: '만료 없음',
    expired: '만료됨',
    editSecret: '수정',
    reveal10s: '10초간 보기',
    maskNow: '가리기',
    copy30s: '복사 (30초 후 자동 비우기)',
    deleteSecret: '삭제',
    importModalTitle: '.env 일괄 가져오기 (Import)',
    importModalPlaceholder: 'DATABASE_URL=postgres://...\nAPI_KEY=sk_live_...',
    cancel: '취소',
    importSubmit: '일괄 저장',
    tokensDesc: 'CLI(mkv) 또는 CI/CD용 서비스 토큰을 발급합니다. 원문 토큰은 생성 직후 1회만 표시됩니다.',
    tokenBannerTitle: '지금 바로 토큰을 복사하세요 — 창을 닫으면 다시 확인할 수 없습니다:',
    copy: '복사',
    copied: '복사됨',
    tokenNamePlaceholder: '토큰 이름 (예: github-ci)',
    allEnvironments: '모든 환경',
    allowedIPsPlaceholder: '허용 IP/CIDR (선택, 쉼표 구분)',
    issueToken: '발급',
    colName: '이름',
    colScope: '권한',
    colEnv: '환경',
    colAllowedIPs: '허용 IP',
    colRevoke: '폐기',
    noTokens: '발급된 서비스 토큰이 없습니다.',
    anyIP: '제한 없음',
    revoke: '폐기',
    webhooksDesc: '시크릿 변경 및 D-7/D-1 만료 임박 알림을 수신합니다. 시크릿 평문 값은 페이로드에 절대 포함되지 않습니다.',
    webhookSecretPlaceholder: 'HMAC 시크릿 키 (custom용)',
    addWebhook: '등록',
    testSent: '테스트 웹훅이 정상적으로 발송되었습니다.',
    testFailed: '테스트 발송 실패',
    colType: '유형',
    colTarget: '대상 URL / 이메일',
    colHmacSecret: 'HMAC 시크릿 키',
    noWebhooks: '등록된 웹훅이 없습니다.',
    testBtn: '테스트',
    auditDesc: '관리자 로그인 시도(성공/실패 IP) 및 시크릿 조회·변경 이력을 확인합니다.',
    refresh: '새로고침',
    colTime: '시간',
    colEvent: '이벤트',
    colActor: '수행자',
    colIP: 'IP 주소',
    colTargetDetail: '대상 / 상세',
    colStatus: '상태',
    noAuditLogs: '기록된 감사 로그가 없습니다.',
    securityTitle: '관리자 2단계 인증 (Google OTP) 재설정',
    securityDesc: 'OTP 기기를 변경하거나 시크릿 키를 재발급하려면 현재 관리자 비밀번호 또는 현재 유효한 OTP 코드로 본인 확인을 진행하세요.',
    reverifyPassword: '현재 관리자 비밀번호',
    reverifyOTP: '또는 현재 6자리 OTP 코드',
    startOTPReset: '새 OTP QR 코드 발급',
    confirmOTPResetTitle: '새 Google OTP 등록 확인',
    confirmOTPResetDesc: '새 QR 코드를 스캔한 뒤 생성된 6자리 코드를 입력해야 변경이 확정됩니다. 취소하면 기존 OTP가 그대로 유지됩니다.',
    confirmResetBtn: 'OTP 변경 확정',
    otpResetSuccess: 'Google OTP 시크릿 키가 안전하게 변경되었습니다.',
    editModalTitle: '시크릿 수정',
    keyReadOnlyHint: 'Key 이름은 식별자이므로 변경할 수 없습니다.',
    expiresAtLabel: '만료일자 (선택)',
    clearDate: '만료일 해제',
    saveChanges: '변경사항 저장',
    quickGuideTitle: '사용 가이드 / Quick Guide',
    sidebarGuide: '프로젝트를 만든 뒤 local, dev, staging, prod 환경을 추가해 시크릿을 분리 관리하세요.',
    secretsGuide1: 'Key는 영문자 또는 "_"로 시작해야 하며 영문·숫자·"_"만 허용됩니다. (예: BLOG_ID, OPENAI_API_KEY)',
    secretsGuide2: 'Value 입력창에서는 오타 방지를 위해 평문이 표시되며 한글·특수문자·멀티라인 입력을 지원합니다. 저장 후 목록에서는 마스킹됩니다.',
    secretsGuideCmdLabel: '서버에서 .env 파일 없이 메모리 주입 실행 예시:',
    tokensGuide1: '발급된 토큰은 현재 선택된 프로젝트에 자동 귀속됩니다. (CLI 실행 시 -p 옵션 불필요)',
    tokensGuide2: '원문 토큰(mkv_...)은 발급 직후 딱 1번만 표시되므로 즉시 복사해 안전하게 보관하세요.',
    tokensGuideCmdLabel: '로컬 또는 서버에서 CLI 최초 1회 로그인 명령어:',
    securityGuide1: 'Google Authenticator 또는 호환 OTP 앱으로 QR 코드를 스캔하여 2단계 인증을 등록합니다.',
    securityGuide2: 'OTP 재설정 시 새 6자리 코드 검증을 완료하기 전에 창을 닫으면 기존 OTP가 그대로 유지됩니다.',
    menuProjects: '프로젝트 / 환경',
  },
  en: {
    appSubtitle: 'Encrypted .env Secret Manager',
    verifyingSession: 'Verifying session...',
    adminPassword: 'Admin Password',
    enterAdminPassword: 'Enter ADMIN_PASSWORD',
    signIn: 'Sign In',
    signingIn: 'Signing in...',
    loginFooter: 'Protected by HttpOnly Strict Session & Brute-Force Rate Limiting',
    totpSetupTitle: 'Set Up Google OTP (2FA)',
    totpSetupDesc: 'Scan this QR code with Google Authenticator (or compatible app) and enter the 6-digit code to complete setup.',
    totpManualSecret: 'Manual Entry Secret',
    totpCodeLabel: '6-Digit OTP Code',
    totpVerifyTitle: 'Two-Factor Authentication',
    totpVerifyDesc: 'Enter the 6-digit verification code from your authenticator app.',
    verifyAndContinue: 'Verify & Sign In',
    verifying: 'Verifying...',
    backToLogin: 'Back to Login',
    projects: 'Projects',
    newProjectPlaceholder: 'New project...',
    createFirstProject: 'Create your first project below.',
    environments: 'Environments',
    customEnvPlaceholder: 'Custom env...',
    signOut: 'Sign out',
    selectProjectPrompt: 'Select or create a project in the sidebar to get started.',
    selectEnvPrompt: 'Create or select an environment (local, dev, staging, prod) in the sidebar.',
    tabSecrets: 'Secrets',
    tabTokens: 'Service Tokens',
    tabWebhooks: 'Webhooks',
    tabAudit: 'Audit Logs',
    tabSecurity: 'Security / OTP',
    secretsDesc: 'Values stay masked in the table. Revealed values auto-mask after 10s; clipboard clears after 30s.',
    clipboardClearsIn: 'Clipboard clears in {sec}s',
    importEnv: 'Import .env',
    exportEnv: 'Export .env',
    keyPlaceholder: 'KEY_NAME (A-Z, 0-9, _)',
    valuePlaceholder: 'Secret value (visible while typing · supports Korean/IME & multiline)',
    uppercaseBtn: 'UPPER',
    saveSecret: 'Save',
    updateSecret: 'Update',
    cancelEdit: 'Cancel',
    invalidKeyError: "Key must start with a letter or '_' and contain only letters, digits, and '_'.",
    colKey: 'Key',
    colValue: 'Value',
    colExpiration: 'Expiration',
    colActions: 'Actions',
    loadingSecrets: 'Loading secrets...',
    noSecrets: 'No secrets in this environment yet.',
    neverExpires: 'Never',
    expired: 'Expired',
    editSecret: 'Edit',
    reveal10s: 'Reveal for 10s',
    maskNow: 'Mask',
    copy30s: 'Copy (auto-clears in 30s)',
    deleteSecret: 'Delete',
    importModalTitle: 'Import .env',
    importModalPlaceholder: 'DATABASE_URL=postgres://...\nAPI_KEY=sk_live_...',
    cancel: 'Cancel',
    importSubmit: 'Import Secrets',
    tokensDesc: 'Issue scoped tokens for CLI (mkv) or CI/CD runners. Plaintext tokens are shown only once.',
    tokenBannerTitle: 'Copy this token now — it will never be shown again:',
    copy: 'Copy',
    copied: 'Copied',
    tokenNamePlaceholder: 'Token name (e.g. github-ci)',
    allEnvironments: 'All environments',
    allowedIPsPlaceholder: 'Allowed IPs/CIDRs (optional)',
    issueToken: 'Issue',
    colName: 'Name',
    colScope: 'Scope',
    colEnv: 'Environment',
    colAllowedIPs: 'Allowed IPs',
    colRevoke: 'Revoke',
    noTokens: 'No service tokens issued for this project.',
    anyIP: 'Any',
    revoke: 'Revoke',
    webhooksDesc: 'Receive secret rotation & D-7/D-1 expiration alerts. Plaintext secret values are never included.',
    webhookSecretPlaceholder: 'HMAC secret key (for custom)',
    addWebhook: 'Add',
    testSent: 'Test webhook event delivered successfully.',
    testFailed: 'Test failed',
    colType: 'Type',
    colTarget: 'Target',
    colHmacSecret: 'HMAC Secret Key',
    noWebhooks: 'No webhooks registered.',
    testBtn: 'Test',
    auditDesc: 'Authentication attempts (success/failure IPs) and secret view/change history.',
    refresh: 'Refresh',
    colTime: 'Time',
    colEvent: 'Event',
    colActor: 'Actor',
    colIP: 'IP Address',
    colTargetDetail: 'Target / Detail',
    colStatus: 'Status',
    noAuditLogs: 'No audit events recorded yet.',
    securityTitle: 'Admin 2FA (Google OTP) Settings',
    securityDesc: 'Re-verify with your current admin password or current 6-digit OTP code before rotating your TOTP secret.',
    reverifyPassword: 'Current Admin Password',
    reverifyOTP: 'Or Current 6-Digit OTP Code',
    startOTPReset: 'Generate New OTP QR Code',
    confirmOTPResetTitle: 'Confirm New Google OTP',
    confirmOTPResetDesc: 'Scan the new QR code and enter the 6-digit code to overwrite your existing OTP. Closing now keeps the current OTP.',
    confirmResetBtn: 'Confirm OTP Change',
    otpResetSuccess: 'Google OTP secret has been rotated successfully.',
    editModalTitle: 'Edit Secret',
    keyReadOnlyHint: 'Key name is read-only as the secret identifier.',
    expiresAtLabel: 'Expiration Date (Optional)',
    clearDate: 'Clear date',
    saveChanges: 'Save Changes',
    quickGuideTitle: 'Quick Guide',
    sidebarGuide: 'Create a project, then add environments (local, dev, staging, prod) to isolate secrets.',
    secretsGuide1: 'Keys must follow ^[A-Za-z_][A-Za-z0-9_]*$ (e.g., BLOG_ID, OPENAI_API_KEY).',
    secretsGuide2: 'Values are visible while typing to prevent typos and support Korean/IME & multiline text. Saved values stay masked in the list.',
    secretsGuideCmdLabel: 'Run your app without writing a .env file to disk:',
    tokensGuide1: 'Service tokens are automatically bound to the currently selected project (no -p flag needed).',
    tokensGuide2: 'The plaintext token (mkv_...) is shown only once upon creation. Copy and store it securely.',
    tokensGuideCmdLabel: 'Authenticate the mkv CLI once:',
    securityGuide1: 'Scan the QR code using Google Authenticator or any standard TOTP app.',
    securityGuide2: 'When rotating OTP, closing before confirming the new 6-digit code keeps your existing OTP active.',
    menuProjects: 'Projects & Envs',
  },
}

const I18nContext = createContext({
  lang: 'ko',
  setLang: () => {},
  t: (key) => key,
})

export function I18nProvider({ children }) {
  const [lang, setLangState] = useState(getInitialLang)

  function setLang(next) {
    setLangState(next)
    try {
      localStorage.setItem(STORAGE_KEY, next)
    } catch {
      // ignore storage errors
    }
  }

  function t(key, vars) {
    let str = translations[lang]?.[key] ?? translations.en[key] ?? key
    if (vars) {
      Object.entries(vars).forEach(([k, v]) => {
        str = str.replace(`{${k}}`, String(v))
      })
    }
    return str
  }

  return (
    <I18nContext.Provider value={{ lang, setLang, t }}>
      {children}
    </I18nContext.Provider>
  )
}

export function useI18n() {
  return useContext(I18nContext)
}

export function LangSwitch() {
  const { lang, setLang } = useI18n()
  return (
    <div className="inline-flex items-center rounded-lg border border-slate-700 bg-slate-900 p-0.5 text-xs font-medium">
      <button
        type="button"
        onClick={() => setLang('ko')}
        className={`rounded-md px-2 py-1 transition cursor-pointer ${
          lang === 'ko' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
        }`}
      >
        KO
      </button>
      <button
        type="button"
        onClick={() => setLang('en')}
        className={`rounded-md px-2 py-1 transition cursor-pointer ${
          lang === 'en' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
        }`}
      >
        EN
      </button>
    </div>
  )
}
