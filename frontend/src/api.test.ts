import axios, { AxiosError, type AxiosAdapter, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, hasSessionHint, logoutAccount, restoreSession, setAccessToken } from './api'

const originalAdapter = api.defaults.adapter
const session = {
  access_token: 'refreshed-access-token',
  token_type: 'bearer',
  user: {
    id: 1,
    full_name: 'Code Owner',
    email: 'owner@example.com',
    theme: 'dark' as const,
    created_at: '2026-01-01T00:00:00Z',
  },
}

afterEach(() => {
  api.defaults.adapter = originalAdapter
  setAccessToken('')
  vi.restoreAllMocks()
})

function unauthorized(config: InternalAxiosRequestConfig): AxiosError {
  const response: AxiosResponse = {
    data: { detail: 'Authentication required.' },
    status: 401,
    statusText: 'Unauthorized',
    headers: {},
    config,
  }
  return new AxiosError('Request failed with status code 401', AxiosError.ERR_BAD_REQUEST, config, undefined, response)
}

describe('session refresh handling', () => {
  it('attempts one startup refresh without a session hint for existing cookie sessions', async () => {
    window.localStorage.removeItem('cg.session-present')
    const request = vi.spyOn(axios, 'post').mockResolvedValue({ data: session } as never)

    await expect(restoreSession()).resolves.toEqual(session)
    expect(request).toHaveBeenCalledTimes(1)
    expect(hasSessionHint()).toBe(true)
  })

  it('coalesces concurrent startup refreshes and retains a valid session', async () => {
    setAccessToken('login-access-token')
    let resolveRefresh!: (value: { data: typeof session }) => void
    const request = vi.spyOn(axios, 'post').mockReturnValue(
      new Promise(resolve => {
        resolveRefresh = resolve
      }) as never,
    )

    const first = restoreSession()
    const second = restoreSession()
    resolveRefresh({ data: session })

    await expect(first).resolves.toEqual(session)
    await expect(second).resolves.toEqual(session)
    expect(request).toHaveBeenCalledTimes(1)
    expect(hasSessionHint()).toBe(true)
  })

  it('clears the session hint when the refresh token is rejected', async () => {
    window.localStorage.removeItem('cg.session-present')
    const request = vi.spyOn(axios, 'post').mockRejectedValue(new Error('Unauthorized'))

    const first = restoreSession()
    const second = restoreSession()
    await expect(first).rejects.toThrow('Unauthorized')
    await expect(second).rejects.toThrow('Unauthorized')
    expect(request).toHaveBeenCalledTimes(1)
    expect(hasSessionHint()).toBe(false)
  })

  it('does not retry refresh on later app starts after a known logged-out state', async () => {
    setAccessToken('')
    const request = vi.spyOn(axios, 'post')

    await expect(restoreSession()).resolves.toBeNull()
    expect(request).not.toHaveBeenCalled()
  })

  it('clears local session state even if the logout request fails', async () => {
    setAccessToken('login-access-token')
    vi.spyOn(api, 'post').mockRejectedValue(new Error('Network error'))

    await expect(logoutAccount()).rejects.toThrow('Network error')
    expect(hasSessionHint()).toBe(false)
  })

  it('does not refresh or retry protected requests when logged out', async () => {
    const refresh = vi.spyOn(axios, 'post')
    api.defaults.adapter = (async config => {
      throw unauthorized(config)
    }) as AxiosAdapter

    await expect(api.get('/api/dashboard')).rejects.toMatchObject({ response: { status: 401 } })
    expect(refresh).not.toHaveBeenCalled()
  })

  it('refreshes once and retries a protected request with the new access token', async () => {
    setAccessToken('expired-access-token')
    const refresh = vi.spyOn(axios, 'post').mockResolvedValue({ data: session } as never)
    let protectedRequests = 0
    api.defaults.adapter = (async config => {
      protectedRequests += 1
      if (config.headers.get('Authorization') !== `Bearer ${session.access_token}`) {
        throw unauthorized(config)
      }
      return {
        data: { ok: true },
        status: 200,
        statusText: 'OK',
        headers: {},
        config,
      }
    }) as AxiosAdapter

    await expect(api.get('/api/dashboard')).resolves.toMatchObject({ data: { ok: true } })
    expect(refresh).toHaveBeenCalledTimes(1)
    expect(protectedRequests).toBe(2)
    expect(hasSessionHint()).toBe(true)
  })
})
