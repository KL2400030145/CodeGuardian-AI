import { Component, CSSProperties, FormEvent, ReactNode, useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowDownToLine, ArrowRight, CheckCircle2,
  ChevronRight, CircleHelp, Code2, FileBarChart2, FileCode2, FolderCode, KeyRound, LayoutDashboard,
  LoaderCircle, LockKeyhole, LogOut, Mail, Menu, Plus, ScanSearch, Search, Settings, Shield,
  ShieldAlert, ShieldCheck, Trash2, Upload, UserRound, X, Eye, EyeOff,
} from 'lucide-react'
import {
  Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import {
  BrowserRouter, Link, Navigate, NavLink, Outlet, Route, Routes, useLocation, useNavigate, useOutletContext,
} from 'react-router-dom'
import {
  ActivityEntry, api, Dashboard, createProject, deleteAccount, deleteProject, downloadReport, explainFinding,
  getActivity, getDashboard, getErrorMessage, getProjects, getScans, getSessions, loginAccount,
  logoutAccount, Project, registerAccount, restoreSession, revokeSession, Scan, setAccessToken,
  updateProfile, uploadScan, User, changePassword,
} from './api'
import { getPasswordStrength, validateRegistration } from './auth'

const navigation = [
  { label: 'Overview', to: '/', icon: LayoutDashboard },
  { label: 'Projects', to: '/projects', icon: FolderCode },
  { label: 'Code Scans', to: '/scans', icon: ScanSearch },
  { label: 'Vulnerabilities', to: '/vulnerabilities', icon: ShieldAlert },
  { label: 'AI Code Review', to: '/ai-review', icon: Code2 },
  { label: 'Reports', to: '/reports', icon: FileBarChart2 },
  { label: 'Activity', to: '/activity', icon: Activity },
  { label: 'Settings', to: '/settings', icon: Settings },
  { label: 'Profile', to: '/profile', icon: UserRound },
]

export default function App() {
  return <BrowserRouter><AppRoutes /></BrowserRouter>
}

function AppRoutes() {
  const [user, setUser] = useState<User | null>(null)
  const [ready, setReady] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    let active = true
    restoreSession()
      .then(session => {
        if (!active || !session) return
        setAccessToken(session.access_token)
        setUser(session.user)
      })
      .catch(() => {
        setAccessToken('')
      })
      .finally(() => active && setReady(true))
    const handleExpired = () => {
      setAccessToken('')
      setUser(null)
      navigate('/login', { replace: true })
    }
    window.addEventListener('cg:session-expired', handleExpired)
    return () => {
      active = false
      window.removeEventListener('cg:session-expired', handleExpired)
    }
  }, [navigate])

  const authenticated = (nextUser: User, token: string) => {
    setAccessToken(token)
    setUser(nextUser)
    navigate('/', { replace: true })
  }

  const signOut = async () => {
    try {
      await logoutAccount()
    } finally {
      setAccessToken('')
      setUser(null)
      navigate('/login', { replace: true })
    }
  }

  if (!ready) return <div className="app-loading"><LoaderCircle className="spin" /> Preparing your secure workspace…</div>

  return (
    <ErrorBoundary>
      <Routes>
        <Route path="/login" element={user ? <Navigate to="/" replace /> : <AuthPage mode="login" onAuthenticated={authenticated} />} />
        <Route path="/register" element={user ? <Navigate to="/" replace /> : <AuthPage mode="register" onAuthenticated={authenticated} />} />
        <Route element={user ? <AppLayout user={user} onLogout={signOut} /> : <Navigate to="/login" replace />}>
          <Route index element={<OverviewPage />} />
          <Route path="/projects" element={<ProjectsPage />} />
          <Route path="/scans" element={<ScansPage />} />
          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="/ai-review" element={<AIReviewPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/activity" element={<ActivityPage />} />
          <Route path="/settings" element={<SettingsPage onUpdated={setUser} />} />
          <Route path="/profile" element={<ProfilePage onUpdated={setUser} onDeleted={signOut} />} />
        </Route>
        <Route path="*" element={<Navigate to={user ? '/' : '/login'} replace />} />
      </Routes>
    </ErrorBoundary>
  )
}

function AuthPage({ mode, onAuthenticated }: { mode: 'login' | 'register'; onAuthenticated: (user: User, token: string) => void }) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [terms, setTerms] = useState(false)
  const [remember, setRemember] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [forgotOpen, setForgotOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const isRegister = mode === 'register'
  const strength = getPasswordStrength(password)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    if (isRegister) {
      const validation = validateRegistration({
        fullName: name,
        email,
        password,
        confirmPassword,
        termsAccepted: terms,
      })
      if (validation) {
        setError(validation)
        return
      }
    } else if (!email.trim() || !password) {
      setError('Enter your email address and password.')
      return
    }
    setBusy(true)
    try {
      const session = isRegister
        ? await registerAccount({ full_name: name.trim(), email: email.trim(), password, terms_accepted: terms })
        : await loginAccount({ email: email.trim(), password, remember_me: remember })
      onAuthenticated(session.user, session.access_token)
    } catch (requestError) {
      setError(await getErrorMessage(requestError))
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="auth-page">
      <div className="auth-glow auth-glow-one" /><div className="auth-glow auth-glow-two" />
      <div className="auth-layout">
        <section className="auth-story">
          <Brand />
          <div className="auth-story-copy">
            <span className="eyebrow"><ShieldCheck size={14} /> APPLICATION SECURITY, MADE CLEAR</span>
            <h1>Secure code.<br /><span>Ship with confidence.</span></h1>
            <p>Find risk earlier, understand what matters, and keep every code review grounded in real scan results.</p>
            <div className="trust-row"><div className="trust-icon"><LockKeyhole size={17} /></div><div><b>Your code stays yours</b><small>Uploads are analyzed as data and never executed.</small></div></div>
          </div>
          <div className="auth-footnote">CODEGUARDIAN AI <span>·</span> SECURITY REVIEW WORKSPACE</div>
        </section>
        <section className="auth-card">
          <div className="auth-mobile-brand"><Brand /></div>
          <div className="auth-card-heading">
            <div className="eyebrow">{isRegister ? 'GET STARTED' : 'WELCOME BACK'}</div>
            <h2>{isRegister ? 'Create your account' : 'Sign in to CodeGuardian'}</h2>
            <p>{isRegister ? 'Set up a secure workspace for your code.' : 'Your security workspace is ready when you are.'}</p>
          </div>
          {error && <Notice kind="error" message={error} />}
          {forgotOpen && <Notice kind="info" message="Password reset email delivery is not configured. No reset email has been sent." />}
          <form onSubmit={submit} className="auth-form">
            {isRegister && <label className="field"><span>Full name</span><div className="input-wrap"><UserRound size={17} /><input autoComplete="name" value={name} onChange={event => setName(event.target.value)} placeholder="Your name" required /></div></label>}
            <label className="field"><span>Email address</span><div className="input-wrap"><Mail size={17} /><input type="email" autoComplete="email" value={email} onChange={event => setEmail(event.target.value)} placeholder="you@company.com" required /></div></label>
            <label className="field"><span>Password</span><div className="input-wrap"><KeyRound size={17} /><input type={showPassword ? 'text' : 'password'} autoComplete={isRegister ? 'new-password' : 'current-password'} value={password} onChange={event => setPassword(event.target.value)} placeholder="Enter your password" required /><button className="field-action" type="button" aria-label={showPassword ? 'Hide password' : 'Show password'} onClick={() => setShowPassword(!showPassword)}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></label>
            {isRegister && <>
              <div className="strength-wrap" aria-live="polite">
                <div className="strength-label"><span>Password strength</span><b>{password ? ['Needs work', 'Fair', 'Good', 'Strong', 'Excellent'][strength] : 'At least 12 characters'}</b></div>
                <div className="strength-bars">{[1, 2, 3, 4].map(level => <i key={level} className={strength >= level ? `filled strength-${strength}` : ''} />)}</div>
                <small>Use 12+ characters with uppercase, lowercase, and a number.</small>
              </div>
              <label className="field"><span>Confirm password</span><div className="input-wrap"><KeyRound size={17} /><input type={showPassword ? 'text' : 'password'} autoComplete="new-password" value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} placeholder="Repeat your password" required /></div></label>
              <label className="check-row"><input type="checkbox" checked={terms} onChange={event => setTerms(event.target.checked)} /><span>I agree to the terms and understand this tool provides security guidance, not a guarantee.</span></label>
            </>}
            {!isRegister && <div className="form-options"><label className="check-row"><input type="checkbox" checked={remember} onChange={event => setRemember(event.target.checked)} /><span>Remember me</span></label><button type="button" className="text-button" onClick={() => setForgotOpen(!forgotOpen)}>Forgot password?</button></div>}
            <button type="submit" className="button button-primary auth-submit" disabled={busy}>{busy ? <><LoaderCircle className="spin" size={17} /> {isRegister ? 'Creating account…' : 'Signing in…'}</> : <>{isRegister ? 'Create account' : 'Sign in'} <ArrowRight size={17} /></>}</button>
          </form>
          <p className="auth-switch">{isRegister ? 'Already have an account?' : 'New to CodeGuardian?'} <Link to={isRegister ? '/login' : '/register'}>{isRegister ? 'Sign in' : 'Create an account'}</Link></p>
          <div className="auth-security"><ShieldCheck size={15} /> Encrypted session · Argon2 password protection</div>
        </section>
      </div>
    </main>
  )
}

function AppLayout({ user, onLogout }: { user: User; onLogout: () => void }) {
  const [menuOpen, setMenuOpen] = useState(false)
  const location = useLocation()
  const initials = user.full_name.split(/\s+/).slice(0, 2).map(part => part[0]).join('').toUpperCase()
  return (
    <div className={`app-shell theme-${user.theme}`}>
      <aside className={`sidebar ${menuOpen ? 'sidebar-open' : ''}`}>
        <Brand />
        <div className="workspace-picker"><span className="status-dot" /> Personal workspace <ChevronRight className="workspace-chevron" size={15} /></div>
        <div className="nav-caption">WORKSPACE</div>
        <nav className="side-nav" aria-label="Main navigation">
          {navigation.map(({ label, to, icon: Icon }) => <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} onClick={() => setMenuOpen(false)}><Icon size={18} /><span>{label}</span></NavLink>)}
        </nav>
        <div className="sidebar-bottom">
          <div className="privacy-card"><div className="privacy-icon"><LockKeyhole size={17} /></div><b>Your code stays yours</b><p>Source is analyzed as data and never executed.</p><span><i className="status-dot" /> PRIVATE WORKSPACE</span></div>
          <div className="sidebar-user"><div className="avatar">{initials}</div><div className="sidebar-user-info"><b>{user.full_name}</b><small>{user.email}</small></div><button className="icon-button logout-button" onClick={onLogout} aria-label="Log out" title="Log out"><LogOut size={17} /></button></div>
        </div>
      </aside>
      <div className="main-column">
        <header className="topbar"><button className="icon-button menu-button" onClick={() => setMenuOpen(!menuOpen)} aria-label="Toggle navigation">{menuOpen ? <X size={19} /> : <Menu size={19} />}</button><div className="breadcrumb"><span>Workspace</span><ChevronRight size={14} /><b>{navigation.find(item => item.to === location.pathname)?.label ?? 'Overview'}</b></div><div className="topbar-right"><span className="secure-indicator"><i className="status-dot" /> Secure workspace</span><div className="avatar avatar-small" title={user.full_name}>{initials}</div></div></header>
        <main className="page-content"><Outlet context={{ user, onLogout }} /></main>
      </div>
    </div>
  )
}

function useWorkspace() {
  return useOutletContext<{ user: User; onLogout: () => void }>()
}

function OverviewPage() {
  const { user } = useWorkspace()
  const [dashboard, setDashboard] = useState<Dashboard | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [drag, setDrag] = useState(false)
  const [scanError, setScanError] = useState('')
  const [scanNotice, setScanNotice] = useState('')
  const navigate = useNavigate()
  const load = async () => {
    try {
      setDashboard(await getDashboard())
      setError('')
    } catch (requestError) {
      setError(await getErrorMessage(requestError))
    }
  }
  useEffect(() => { void load() }, [])

  async function scanFile(file?: File) {
    if (!file) return
    setBusy(true)
    setScanError('')
    setScanNotice('')
    try {
      const scan = await uploadScan(file)
      setScanNotice(scan.summary)
      await load()
    } catch (requestError) {
      setScanError(await getErrorMessage(requestError))
    } finally {
      setBusy(false)
    }
  }

  const severities = dashboard?.severity_counts ?? {}
  const severityData = [
    { name: 'Critical', value: severities.critical ?? 0, color: '#fb7185' },
    { name: 'High', value: severities.high ?? 0, color: '#fb923c' },
    { name: 'Medium', value: severities.medium ?? 0, color: '#facc15' },
    { name: 'Low', value: severities.low ?? 0, color: '#818cf8' },
  ]
  const greeting = new Date().getHours() < 12 ? 'Good morning' : new Date().getHours() < 18 ? 'Good afternoon' : 'Good evening'

  return <>
    <PageHeading eyebrow="SECURITY OVERVIEW" title={`${greeting}, ${user.full_name.split(' ')[0]}.`} description="Stay ahead of risk across your codebase." action={<label className="button button-primary"><Upload size={17} /> New code scan<input hidden type="file" accept=".py,.zip" onChange={event => scanFile(event.target.files?.[0])} /></label>} />
    {error && <Notice kind="error" message={error} />}
    <div className="metric-grid">
      <MetricCard label="Total projects" value={dashboard?.total_projects ?? '—'} icon={<FolderCode />} note="Your active codebases" />
      <MetricCard label="Total scans" value={dashboard?.total_scans ?? '—'} icon={<ScanSearch />} note="All recorded security scans" />
      <MetricCard label="Vulnerabilities" value={dashboard?.total_vulnerabilities ?? '—'} icon={<ShieldAlert />} note="Findings across all scans" tone="orange" />
      <MetricCard label="Security score" value={dashboard ? `${dashboard.security_score}` : '—'} icon={<ShieldCheck />} note="Risk-weighted score out of 100" tone="green" />
    </div>
    <div className="dashboard-grid">
      <section className="panel scan-panel">
        <div className="section-heading"><div><h2>Start a security scan</h2><p>Review Python source files or a ZIP repository.</p></div><span className="tag"><Shield size={14} /> PYTHON ANALYSIS</span></div>
        <div className={`drop-zone ${drag ? 'dragging' : ''} ${busy ? 'is-busy' : ''}`} onDragOver={event => { event.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)} onDrop={event => { event.preventDefault(); setDrag(false); void scanFile(event.dataTransfer.files[0]) }}>
          <div className="upload-symbol">{busy ? <LoaderCircle className="spin" size={24} /> : <Upload size={24} />}</div><b>{busy ? 'Analyzing your code…' : 'Drop your source or archive here'}</b><span>or <label className="inline-link">browse files<input hidden type="file" accept=".py,.zip" disabled={busy} onChange={event => scanFile(event.target.files?.[0])} /></label></span><small>Python .py and .zip · up to 15 MB · code is never executed</small>
        </div>
        {scanError && <Notice kind="error" message={scanError} />}
        {scanNotice && <Notice kind="success" message={scanNotice} />}
        <div className="scan-engine-note"><LockKeyhole size={15} /> Built-in rules, Bandit, Ruff, Radon <span>Optional Semgrep when installed</span></div>
      </section>
      <section className="panel severity-panel">
        <div className="section-heading"><div><h2>Finding severity</h2><p>Distribution across your scans</p></div><span className="subtle-count">{dashboard?.total_vulnerabilities ?? 0} total</span></div>
        <div className="severity-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={severityData}><CartesianGrid stroke="#253149" strokeDasharray="4 5" vertical={false} /><XAxis dataKey="name" stroke="#8b98ad" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} /><YAxis allowDecimals={false} stroke="#8b98ad" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} /><Tooltip contentStyle={{ background: '#101a2b', border: '1px solid #293650', borderRadius: 10, color: '#eef2ff' }} /><Bar dataKey="value" radius={[6, 6, 0, 0]}>{severityData.map(entry => <Cell key={entry.name} fill={entry.color} />)}</Bar></BarChart></ResponsiveContainer></div>
        <div className="severity-legend">{severityData.map(item => <span key={item.name}><i style={{ background: item.color }} />{item.name} <b>{item.value}</b></span>)}</div>
      </section>
    </div>
    <div className="dashboard-grid dashboard-lower">
      <section className="panel recent-panel"><div className="section-heading"><div><h2>Recent scans</h2><p>Your latest code security activity.</p></div><Link className="inline-link" to="/scans">View all <ArrowRight size={15} /></Link></div>
        {dashboard?.recent_scans.length ? <div className="scan-list">{dashboard.recent_scans.map(scan => <button key={scan.id} className="scan-row" onClick={() => navigate('/scans', { state: { scanId: scan.id } })}><div className="scan-file-icon"><FileCode2 size={18} /></div><span className="scan-row-info"><b>{scan.filename}</b><small>{scan.summary}</small></span><span className={`scan-status status-${scan.status}`}>{scan.status.replace(/_/g, ' ')}</span><span className="finding-count">{scan.findings.length} findings</span><ChevronRight size={16} /></button>)}</div> : <EmptyState icon={<ScanSearch />} title="No scans yet" description="Upload a Python file or ZIP archive to create your first security report." action={<label className="button button-secondary"><Upload size={16} /> Upload code<input hidden type="file" accept=".py,.zip" onChange={event => scanFile(event.target.files?.[0])} /></label>} />}
      </section>
      <section className="panel score-panel"><div className="section-heading"><div><h2>Security score</h2><p>A transparent, risk-weighted indicator.</p></div><ShieldCheck size={19} className="accent-icon" /></div><div className="score-display"><div className="score-ring" style={{ '--score': `${dashboard?.security_score ?? 0}%` } as CSSProperties}><span><b>{dashboard?.security_score ?? '—'}</b><small>out of 100</small></span></div><div className="score-caption"><b>{dashboard ? dashboard.security_score >= 80 ? 'Strong baseline' : dashboard.security_score >= 50 ? 'Needs attention' : 'High risk detected' : 'Loading score'}</b><small>Based on {dashboard?.total_vulnerabilities ?? 0} stored finding(s).</small></div></div><details className="calculation"><summary>How is this calculated?</summary><p>{dashboard?.score_calculation ?? 'Loading calculation…'}</p></details></section>
    </div>
    <p className="page-disclaimer"><CircleHelp size={15} /> Automated findings are guidance. Validate results and remediations before changing production code.</p>
  </>
}

function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const load = async () => setProjects(await getProjects())
  useEffect(() => { void load().catch(async error => setError(await getErrorMessage(error))) }, [])

  async function addProject(event: FormEvent) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await createProject({ name, description })
      setName('')
      setDescription('')
      setNotice('Project created.')
      await load()
    } catch (requestError) {
      setError(await getErrorMessage(requestError))
    } finally {
      setBusy(false)
    }
  }
  async function removeProject(project: Project) {
    if (!window.confirm(`Delete "${project.name}"? Existing scans remain in your scan history.`)) return
    try {
      await deleteProject(project.id)
      await load()
    } catch (requestError) {
      setError(await getErrorMessage(requestError))
    }
  }
  async function scanProject(project: Project, file?: File) {
    if (!file) return
    setError('')
    try {
      const scan = await uploadScan(file, project.id)
      setNotice(scan.summary)
      await load()
    } catch (requestError) {
      setError(await getErrorMessage(requestError))
    }
  }

  return <>
    <PageHeading eyebrow="YOUR CODEBASES" title="Projects" description="Organize repositories and keep their security history together." />
    {error && <Notice kind="error" message={error} />}{notice && <Notice kind="success" message={notice} />}
    <section className="panel create-project-panel"><div className="section-heading"><div><h2>Create a project</h2><p>Start a workspace for an application or repository.</p></div><Plus size={19} className="accent-icon" /></div><form className="project-form" onSubmit={addProject}><label className="field"><span>Project name</span><input value={name} onChange={event => setName(event.target.value)} maxLength={120} placeholder="e.g. Payments API" required /></label><label className="field"><span>Description <small>(optional)</small></span><input value={description} onChange={event => setDescription(event.target.value)} maxLength={2000} placeholder="What does this project do?" /></label><button className="button button-primary" disabled={busy}>{busy ? <LoaderCircle className="spin" size={16} /> : <Plus size={16} />} Create project</button></form></section>
    <div className="projects-heading"><div><h2>Your projects</h2><p>{projects.length} project{projects.length === 1 ? '' : 's'}</p></div></div>
    {projects.length ? <div className="project-grid">{projects.map(project => <article className="panel project-card" key={project.id}><div className="project-card-top"><div className="project-icon"><FolderCode size={21} /></div><button className="icon-button danger-hover" aria-label={`Delete ${project.name}`} title="Delete project" onClick={() => removeProject(project)}><Trash2 size={16} /></button></div><h3>{project.name}</h3><p>{project.description || 'No description provided.'}</p><div className="project-card-meta"><span><ScanSearch size={14} /> {project.scan_count} scans</span><span>Created {formatDate(project.created_at)}</span></div><label className="button button-secondary project-scan"><Upload size={15} /> Scan repository<input hidden type="file" accept=".py,.zip" onChange={event => scanProject(project, event.target.files?.[0])} /></label></article>)}</div> : <EmptyState icon={<FolderCode />} title="No projects yet" description="Create your first project to organize scans by repository." />}
  </>
}

function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [search, setSearch] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const routeLocation = useLocation()
  const load = async () => setScans(await getScans())
  useEffect(() => {
    void load().catch(async error => setError(await getErrorMessage(error)))
    if (routeLocation.state?.scanId) setSelectedId(routeLocation.state.scanId)
  }, [])
  const selected = scans.find(scan => scan.id === selectedId)
  const filtered = scans.filter(scan => `${scan.filename} ${scan.summary}`.toLowerCase().includes(search.toLowerCase()))

  async function scanFile(file?: File) {
    if (!file) return
    setBusy(true)
    setError('')
    try {
      const scan = await uploadScan(file)
      setSelectedId(scan.id)
      await load()
    } catch (requestError) {
      setError(await getErrorMessage(requestError))
    } finally {
      setBusy(false)
    }
  }

  return <>
    <PageHeading eyebrow="ANALYSIS HISTORY" title="Code scans" description="Review scanner output and persisted security findings." action={<label className="button button-primary"><Upload size={16} /> {busy ? 'Scanning…' : 'New scan'}<input hidden type="file" accept=".py,.zip" disabled={busy} onChange={event => scanFile(event.target.files?.[0])} /></label>} />
    {error && <Notice kind="error" message={error} />}
    <section className="panel">
      <div className="section-heading section-heading-padded"><div><h2>{selected ? selected.filename : 'Scan history'}</h2><p>{selected ? selected.summary : `${scans.length} scan${scans.length === 1 ? '' : 's'} recorded`}</p></div><div className="table-actions">{selected && <button className="button button-secondary" onClick={() => setSelectedId(null)}>All scans</button>}<label className="search-field"><Search size={16} /><input aria-label="Search scans" placeholder="Search scans" value={search} onChange={event => setSearch(event.target.value)} /></label></div></div>
      {selected ? <ScanDetail scan={selected} /> : filtered.length ? <div className="scan-list">{filtered.map(scan => <button key={scan.id} className="scan-row" onClick={() => setSelectedId(scan.id)}><div className="scan-file-icon"><FileCode2 size={18} /></div><span className="scan-row-info"><b>{scan.filename}</b><small>{scan.summary}</small></span><span className={`scan-status status-${scan.status}`}>{scan.status.replace(/_/g, ' ')}</span><span className="finding-count">{scan.findings.length} findings</span><ChevronRight size={16} /></button>)}</div> : <EmptyState icon={<ScanSearch />} title={scans.length ? 'No matching scans' : 'No scans yet'} description={scans.length ? 'Try another search.' : 'Upload Python code or a ZIP archive to begin.'} />}
    </section>
  </>
}

function ScanDetail({ scan }: { scan: Scan }) {
  return <div className="scan-detail"><div className="scanner-statuses"><b>Scanner status</b>{Object.entries(scan.scanners ?? {}).map(([name, status]) => <span key={name}><i className={status.startsWith('failed') ? 'status-failed' : status === 'completed' ? 'status-ok' : 'status-skip'} />{name}: {status}</span>)}</div><div className="table-wrap"><FindingTable findings={scan.findings} /></div><div className="report-actions"><button className="button button-secondary" onClick={() => downloadReport(scan.id, 'json')}><ArrowDownToLine size={16} /> Download JSON</button><button className="button button-secondary" onClick={() => downloadReport(scan.id, 'pdf')}><FileBarChart2 size={16} /> Download PDF</button></div></div>
}

function VulnerabilitiesPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('all')
  const [error, setError] = useState('')
  useEffect(() => { void getScans().then(setScans).catch(async error => setError(await getErrorMessage(error))) }, [])
  const findings = useMemo(() => scans.flatMap(scan => scan.findings.map(finding => ({ ...finding, scanName: scan.filename }))).filter(finding => (severity === 'all' || finding.severity === severity) && `${finding.title} ${finding.rule_id} ${finding.file} ${finding.scanName}`.toLowerCase().includes(search.toLowerCase())), [scans, search, severity])
  return <>
    <PageHeading eyebrow="RISK INVENTORY" title="Vulnerabilities" description="Search findings across your saved scans." />
    {error && <Notice kind="error" message={error} />}
    <section className="panel"><div className="section-heading section-heading-padded"><div><h2>{findings.length} finding{findings.length === 1 ? '' : 's'}</h2><p>Filter and review scanner explanations.</p></div><div className="table-actions"><label className="search-field"><Search size={16} /><input aria-label="Search vulnerabilities" value={search} onChange={event => setSearch(event.target.value)} placeholder="Search findings" /></label><select className="select-field" aria-label="Filter severity" value={severity} onChange={event => setSeverity(event.target.value)}><option value="all">All severities</option>{['critical', 'high', 'medium', 'low'].map(value => <option key={value} value={value}>{capitalize(value)}</option>)}</select></div></div>{findings.length ? <div className="table-wrap"><FindingTable findings={findings} showScan /></div> : <EmptyState icon={<ShieldCheck />} title="No findings to show" description="Scan a Python file or ZIP repository to populate your vulnerability inventory." />}</section>
  </>
}

function AIReviewPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState('')
  const [explanations, setExplanations] = useState<Record<string, string>>({})
  const [error, setError] = useState('')
  useEffect(() => { void getScans().then(setScans).catch(async error => setError(await getErrorMessage(error))).finally(() => setLoading(false)) }, [])

  async function explain(finding: Scan['findings'][number]) {
    const key = `${finding.rule_id}:${finding.file}:${finding.line}`
    setBusyId(key)
    setError('')
    try {
      const explanation = await explainFinding({
        finding: `${finding.title}. ${finding.description} Remediation: ${finding.recommendation}`,
        snippet: finding.snippet,
      })
      setExplanations(previous => ({ ...previous, [key]: explanation }))
    } catch (requestError) {
      setError(await getErrorMessage(requestError))
    } finally {
      setBusyId('')
    }
  }

  const findings = scans.flatMap(scan => scan.findings.map(finding => ({ ...finding, scanName: scan.filename })))
  return <>
    <PageHeading eyebrow="OPTIONAL AI ASSISTANCE" title="AI code review" description="Ask the configured language model to explain a real scanner finding in plain language." />
    <Notice kind="info" message="AI explanations require an OpenAI-compatible provider configured with OPENAI_API_KEY. Source snippets are sent only when you request an explanation." />
    {error && <Notice kind="error" message={error} />}
    {loading ? <LoadingState /> : findings.length ? <div className="ai-finding-list">{findings.slice(0, 40).map(finding => {
      const key = `${finding.rule_id}:${finding.file}:${finding.line}`
      return <article className="panel ai-finding" key={key}><div className="ai-finding-heading"><div><Severity value={finding.severity} /><h3>{finding.title}</h3><p>{finding.scanName} · {finding.file}:{finding.line} · {finding.source}</p></div><button className="button button-secondary" disabled={busyId === key} onClick={() => explain(finding)}>{busyId === key ? <LoaderCircle className="spin" size={16} /> : <Code2 size={16} />} Explain finding</button></div><p className="finding-description">{finding.description}</p>{explanations[key] && <div className="ai-explanation"><b>AI explanation</b><p>{explanations[key]}</p></div>}</article>
    })}</div> : <EmptyState icon={<Code2 />} title="No findings to explain" description="Run a scan first. AI review will only explain findings that were actually recorded." />}
  </>
}

function ReportsPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [error, setError] = useState('')
  useEffect(() => { void getScans().then(setScans).catch(async error => setError(await getErrorMessage(error))) }, [])
  return <>
    <PageHeading eyebrow="REPORT LIBRARY" title="Reports" description="Export reports generated from persisted scan results." />
    {error && <Notice kind="error" message={error} />}
    <section className="panel"><div className="section-heading section-heading-padded"><div><h2>Security reports</h2><p>JSON data and formatted PDF exports.</p></div></div>{scans.length ? <div className="report-list">{scans.map(scan => <div className="report-row" key={scan.id}><div className="report-icon"><FileBarChart2 size={19} /></div><div className="report-info"><b>{scan.filename}</b><small>{scan.findings.length} findings · {formatDate(scan.created_at)} · {scan.status.replace(/_/g, ' ')}</small></div><button className="button button-secondary" onClick={() => downloadReport(scan.id, 'json')}><ArrowDownToLine size={15} /> JSON</button><button className="button button-secondary" onClick={() => downloadReport(scan.id, 'pdf')}><ArrowDownToLine size={15} /> PDF</button></div>)}</div> : <EmptyState icon={<FileBarChart2 />} title="No reports yet" description="Reports become available after your first saved scan." />}</section>
  </>
}

function ActivityPage() {
  const [items, setItems] = useState<ActivityEntry[]>([])
  const [error, setError] = useState('')
  useEffect(() => { void getActivity().then(setItems).catch(async error => setError(await getErrorMessage(error))) }, [])
  return <>
    <PageHeading eyebrow="WORKSPACE AUDIT TRAIL" title="Activity" description="A recent timeline of account and security events." />
    {error && <Notice kind="error" message={error} />}
    <section className="panel activity-panel"><div className="section-heading section-heading-padded"><div><h2>Recent activity</h2><p>Events are scoped to your account.</p></div></div>{items.length ? <div className="activity-list">{items.map(item => <div className="activity-item" key={item.id}><div className="activity-dot"><Activity size={15} /></div><div><b>{item.description}</b><small>{item.action} · {formatDate(item.created_at)}</small></div></div>)}</div> : <EmptyState icon={<Activity />} title="No activity recorded" description="Project and scan events will appear here." />}</section>
  </>
}

function SettingsPage({ onUpdated }: { onUpdated: (user: User) => void }) {
  const { user } = useWorkspace()
  const [theme, setTheme] = useState<User['theme']>(user.theme)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  async function save(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const updated = await updateProfile({ theme })
      onUpdated(updated)
      setNotice('Appearance preference saved.')
    } catch (requestError) {
      setError(await getErrorMessage(requestError))
    } finally {
      setBusy(false)
    }
  }
  return <>
    <PageHeading eyebrow="WORKSPACE PREFERENCES" title="Settings" description="Manage display preferences and security defaults." />
    {error && <Notice kind="error" message={error} />}{notice && <Notice kind="success" message={notice} />}
    <section className="panel settings-card"><div className="section-heading"><div><h2>Appearance</h2><p>Choose your preferred workspace theme.</p></div><Settings size={19} className="accent-icon" /></div><form onSubmit={save} className="settings-form"><label className="field"><span>Theme</span><select className="select-field" value={theme} onChange={event => setTheme(event.target.value as User['theme'])}><option value="dark">Dark navy</option><option value="light">Light</option></select></label><button className="button button-primary" disabled={busy}>{busy ? 'Saving…' : 'Save preference'}</button></form></section>
    <section className="panel settings-card"><div className="section-heading"><div><h2>Account security</h2><p>Refresh tokens are rotated and stored as one-way hashes.</p></div><LockKeyhole size={19} className="accent-icon" /></div><p className="settings-copy">Use the Profile page to change your password, review active sessions, or delete your account. Email changes remain unavailable until a verification email service is configured.</p></section>
  </>
}

function ProfilePage({ onUpdated, onDeleted }: { onUpdated: (user: User) => void; onDeleted: () => void }) {
  const { user } = useWorkspace()
  const [name, setName] = useState(user.full_name)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [sessions, setSessions] = useState<Array<{ id: number; created_at: string | null; expires_at: string; user_agent: string | null }>>([])
  const [deleteEmail, setDeleteEmail] = useState('')
  const [deletePassword, setDeletePassword] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const loadSessions = async () => setSessions(await getSessions())
  useEffect(() => { void loadSessions().catch(async error => setError(await getErrorMessage(error))) }, [])

  async function saveName(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      onUpdated(await updateProfile({ full_name: name }))
      setNotice('Profile updated.')
    } catch (requestError) {
      setError(await getErrorMessage(requestError))
    } finally {
      setBusy(false)
    }
  }
  async function savePassword(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await changePassword({ current_password: currentPassword, new_password: newPassword })
      setCurrentPassword('')
      setNewPassword('')
      setNotice('Password changed. Other sessions have been signed out.')
      await loadSessions()
    } catch (requestError) {
      setError(await getErrorMessage(requestError))
    } finally {
      setBusy(false)
    }
  }
  async function removeAccount(event: FormEvent) {
    event.preventDefault()
    if (!window.confirm('Permanently delete your account, projects, scans, and reports? This cannot be undone.')) return
    setBusy(true)
    setError('')
    try {
      await deleteAccount({ email: deleteEmail, password: deletePassword })
      onDeleted()
    } catch (requestError) {
      setError(await getErrorMessage(requestError))
      setBusy(false)
    }
  }
  async function removeSession(id: number) {
    try {
      await revokeSession(id)
      await loadSessions()
    } catch (requestError) {
      setError(await getErrorMessage(requestError))
    }
  }

  return <>
    <PageHeading eyebrow="PERSONAL ACCOUNT" title="Profile" description="Update your identity and manage authenticated sessions." />
    {error && <Notice kind="error" message={error} />}{notice && <Notice kind="success" message={notice} />}
    <section className="panel settings-card"><div className="section-heading"><div><h2>Profile details</h2><p>Your workspace identity.</p></div><UserRound size={19} className="accent-icon" /></div><form className="settings-form" onSubmit={saveName}><label className="field"><span>Full name</span><input value={name} onChange={event => setName(event.target.value)} minLength={2} maxLength={120} required /></label><label className="field"><span>Email address</span><input value={user.email} disabled /><small>Email updates require verification email delivery, which is not configured.</small></label><button className="button button-primary" disabled={busy}>Save profile</button></form></section>
    <section className="panel settings-card"><div className="section-heading"><div><h2>Change password</h2><p>At least 12 characters, with uppercase, lowercase, and a number.</p></div><KeyRound size={19} className="accent-icon" /></div><form className="settings-form" onSubmit={savePassword}><label className="field"><span>Current password</span><input type="password" autoComplete="current-password" value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} required /></label><label className="field"><span>New password</span><input type="password" autoComplete="new-password" minLength={12} value={newPassword} onChange={event => setNewPassword(event.target.value)} required /></label><button className="button button-primary" disabled={busy || !currentPassword || !newPassword}>Update password</button></form></section>
    <section className="panel settings-card"><div className="section-heading"><div><h2>Active sessions</h2><p>Revoke sessions you no longer recognize.</p></div><Activity size={19} className="accent-icon" /></div>{sessions.length ? <div className="session-list">{sessions.map(session => <div className="session-row" key={session.id}><div><b>{session.user_agent || 'Browser session'}</b><small>Started {formatDate(session.created_at)} · Expires {formatDate(session.expires_at)}</small></div><button className="button button-secondary" onClick={() => removeSession(session.id)}>Revoke</button></div>)}</div> : <p className="settings-copy">No active sessions.</p>}</section>
    <section className="panel settings-card danger-zone"><div className="section-heading"><div><h2>Delete account</h2><p>Permanently remove your projects, scans, and account data.</p></div><Trash2 size={19} /></div><form className="settings-form" onSubmit={removeAccount}><label className="field"><span>Confirm email</span><input type="email" value={deleteEmail} onChange={event => setDeleteEmail(event.target.value)} required /></label><label className="field"><span>Confirm password</span><input type="password" value={deletePassword} onChange={event => setDeletePassword(event.target.value)} required /></label><button className="button button-danger" disabled={busy}>Delete account permanently</button></form></section>
  </>
}

function FindingTable({ findings, showScan = false }: { findings: Array<Scan['findings'][number] & { scanName?: string }>; showScan?: boolean }) {
  return <table><thead><tr><th>FINDING</th>{showScan && <th>SCAN</th>}<th>FILE / LINE</th><th>SEVERITY</th><th>SOURCE</th></tr></thead><tbody>{findings.map((finding, index) => <tr key={`${finding.rule_id}-${finding.file}-${finding.line}-${index}`}><td><b>{finding.title}</b><small>{finding.rule_id} · {finding.description}</small>{finding.snippet && <code className="code-snippet">{finding.snippet}</code>}<small className="recommendation">Fix: {finding.recommendation}</small></td>{showScan && <td>{finding.scanName}</td>}<td className="mono">{finding.file}:{finding.line}</td><td><Severity value={finding.severity} /></td><td className="muted">{finding.source}</td></tr>)}</tbody></table>
}

function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{action}</div>
}

function MetricCard({ label, value, icon, note, tone }: { label: string; value: string | number; icon: ReactNode; note: string; tone?: 'orange' | 'green' }) {
  return <article className="metric-card"><div className="metric-top"><span>{label}</span><i className={tone ?? ''}>{icon}</i></div><strong>{value}</strong><small>{note}</small></article>
}

function Brand() {
  return <Link to="/" className="brand" aria-label="CodeGuardian AI home"><span className="brand-mark"><ShieldCheck size={22} strokeWidth={2.2} /></span><span className="brand-text"><b>CodeGuardian <em>AI</em></b><small>SECURE CODE. SHIP WITH CONFIDENCE.</small></span></Link>
}

function Notice({ kind, message }: { kind: 'error' | 'success' | 'info'; message: string }) {
  const Icon = kind === 'error' ? AlertTriangle : kind === 'success' ? CheckCircle2 : CircleHelp
  return <div className={`notice notice-${kind}`} role={kind === 'error' ? 'alert' : 'status'}><Icon size={17} /><span>{message}</span></div>
}

function EmptyState({ icon, title, description, action }: { icon: ReactNode; title: string; description: string; action?: ReactNode }) {
  return <div className="empty-state"><div className="empty-state-icon">{icon}</div><b>{title}</b><p>{description}</p>{action}</div>
}

function LoadingState() {
  return <div className="loading-state"><LoaderCircle className="spin" size={20} /> Loading workspace data…</div>
}

function Severity({ value }: { value: string }) {
  return <span className={`severity severity-${value.toLowerCase()}`}>{value}</span>
}

function formatDate(value: string | null) {
  if (!value) return 'just now'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function capitalize(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1)
}

class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  render() {
    if (this.state.failed) return <main className="fatal-error"><ShieldAlert size={32} /><h1>Something went wrong</h1><p>Your session and stored scans are safe. Refresh the page to try again.</p><button className="button button-primary" onClick={() => window.location.reload()}>Reload workspace</button></main>
    return this.props.children
  }
}
