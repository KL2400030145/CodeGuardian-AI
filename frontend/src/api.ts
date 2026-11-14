import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios'

const localHosts = new Set(['localhost', '127.0.0.1'])
const baseURL =
  import.meta.env.VITE_API_URL ||
  `http://${localHosts.has(window.location.hostname) ? window.location.hostname : '127.0.0.1'}:8000`

export const api = axios.create({ baseURL, withCredentials: true })

export type User = {
  id: number
  full_name: string
  email: string
  theme: 'dark' | 'light'
  created_at: string
}

export type Finding = {
  rule_id: string
  title: string
  severity: string
  file: string
  line: number
  snippet: string
  description: string
  recommendation: string
  source: string
}

export type Scan = {
  id: number
  filename: string
  language: string
  status: string
  summary: string
  findings: Finding[]
  scanners: Record<string, string>
  project_id: number | null
  created_at: string | null
}

export type Project = {
  id: number
  name: string
  description: string
  created_at: string | null
  scan_count: number
}

export type Dashboard = {
  total_projects: number
  total_scans: number
  total_vulnerabilities: number
  severity_counts: Record<string, number>
  security_score: number
  recent_scans: Scan[]
  activity: ActivityEntry[]
  score_calculation: string
}

export type ActivityEntry = {
  id: number
  action: string
  description: string
  created_at: string | null
}

type AuthResponse = { access_token: string; token_type: string; user: User }

let accessToken = ''
let refreshRequest: Promise<AuthResponse> | undefined
const SESSION_HINT_KEY = 'cg.session-present'

export function hasSessionHint(): boolean {
  return window.localStorage.getItem(SESSION_HINT_KEY) === '1'
}

export function setAccessToken(token: string) {
  accessToken = token
  window.localStorage.setItem(SESSION_HINT_KEY, token ? '1' : '0')
}

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  if (accessToken) config.headers.set('Authorization', `Bearer ${accessToken}`)
  return config
})

api.interceptors.response.use(
  response => response,
  async (error: AxiosError) => {
    const config = error.config as (InternalAxiosRequestConfig & { _retried?: boolean }) | undefined
    if (
      error.response?.status !== 401 ||
      !config ||
      config._retried ||
      config.url?.includes('/api/auth/') ||
      !hasSessionHint()
    ) {
      return Promise.reject(error)
    }
    config._retried = true
    try {
      refreshRequest ??= axios
        .post<AuthResponse>(`${baseURL}/api/auth/refresh`, null, { withCredentials: true })
        .then(response => {
          setAccessToken(response.data.access_token)
          return response.data
        })
        .catch(refreshError => {
          setAccessToken('')
          window.dispatchEvent(new Event('cg:session-expired'))
          throw refreshError
        })
        .finally(() => {
          refreshRequest = undefined
        })
      const session = await refreshRequest
      accessToken = session.access_token
      config.headers.set('Authorization', `Bearer ${accessToken}`)
      return api(config)
    } catch (refreshError) {
      return Promise.reject(refreshError)
    }
  },
)

export async function registerAccount(input: {
  full_name: string
  email: string
  password: string
  terms_accepted: boolean
}): Promise<AuthResponse> {
  const { data } = await api.post<AuthResponse>('/api/auth/register', input)
  return data
}

export async function loginAccount(input: {
  email: string
  password: string
  remember_me: boolean
}): Promise<AuthResponse> {
  const { data } = await api.post<AuthResponse>('/api/auth/login', input)
  return data
}

export async function restoreSession(): Promise<AuthResponse | null> {
  if (window.localStorage.getItem(SESSION_HINT_KEY) === '0') return null
  refreshRequest ??= axios
    .post<AuthResponse>(`${baseURL}/api/auth/refresh`, null, { withCredentials: true })
    .then(response => {
      setAccessToken(response.data.access_token)
      return response.data
    })
    .catch(refreshError => {
      setAccessToken('')
      throw refreshError
    })
    .finally(() => {
      refreshRequest = undefined
    })
  return refreshRequest
}

export async function logoutAccount() {
  try {
    await api.post('/api/auth/logout')
  } finally {
    setAccessToken('')
  }
}

export async function getScans(): Promise<Scan[]> {
  const { data } = await api.get<Scan[]>('/api/scans')
  return data
}

export async function uploadScan(file: File, projectId?: number): Promise<Scan> {
  const formData = new FormData()
  formData.append('file', file)
  const { data } = await api.post<Scan>('/api/scans', formData, {
    params: projectId ? { project_id: projectId } : undefined,
  })
  return data
}

export async function getProjects(): Promise<Project[]> {
  const { data } = await api.get<Project[]>('/api/projects')
  return data
}

export async function createProject(input: { name: string; description: string }): Promise<Project> {
  const { data } = await api.post<Project>('/api/projects', input)
  return data
}

export async function deleteProject(projectId: number) {
  await api.delete(`/api/projects/${projectId}`)
}

export async function getDashboard(): Promise<Dashboard> {
  const { data } = await api.get<Dashboard>('/api/dashboard')
  return data
}

export async function getActivity(): Promise<ActivityEntry[]> {
  const { data } = await api.get<ActivityEntry[]>('/api/activity')
  return data
}

export async function updateProfile(input: { full_name?: string; theme?: 'dark' | 'light' }) {
  const { data } = await api.put<User>('/api/auth/profile', input)
  return data
}

export async function changePassword(input: { current_password: string; new_password: string }) {
  await api.put('/api/auth/password', input)
}

export async function getSessions(): Promise<Array<{
  id: number
  created_at: string | null
  expires_at: string
  user_agent: string | null
}>> {
  const { data } = await api.get('/api/auth/sessions')
  return data
}

export async function revokeSession(sessionId: number) {
  await api.delete(`/api/auth/sessions/${sessionId}`)
}

export async function deleteAccount(input: { email: string; password: string }) {
  try {
    await api.delete('/api/auth/account', { data: input })
  } finally {
    setAccessToken('')
  }
}

export async function explainFinding(input: { finding: string; snippet: string }) {
  const { data } = await api.post<{ explanation: string }>('/api/ai/explain', input)
  return data.explanation
}

export async function downloadReport(scanId: number, format: 'json' | 'pdf') {
  const { data } = await api.get<Blob>(`/api/scans/${scanId}/report.${format}`, {
    responseType: 'blob',
  })
  const url = URL.createObjectURL(data)
  const link = document.createElement('a')
  link.href = url
  link.download = `codeguardian-scan-${scanId}.${format}`
  link.click()
  URL.revokeObjectURL(url)
}

export async function getErrorMessage(error: unknown): Promise<string> {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail) && typeof detail[0]?.msg === 'string') return detail[0].msg
    if (error.response?.status === 503 && error.response.data instanceof Blob) {
      try {
        const body = JSON.parse(await error.response.data.text())
        if (typeof body.detail === 'string') return body.detail
      } catch {
        return 'The service is temporarily unavailable.'
      }
    }
    return error.message || 'The request could not be completed.'
  }
  return error instanceof Error ? error.message : 'The request could not be completed.'
}
