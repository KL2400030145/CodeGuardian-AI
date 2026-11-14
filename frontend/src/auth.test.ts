import { describe, expect, it } from 'vitest'
import { getPasswordStrength, validateRegistration } from './auth'

describe('registration validation', () => {
  const validInput = {
    fullName: 'Code Owner',
    email: 'owner@example.test',
    password: 'SecurePassword123!',
    confirmPassword: 'SecurePassword123!',
    termsAccepted: true,
  }

  it('accepts a valid registration and rates stronger passwords', () => {
    expect(validateRegistration(validInput)).toBeNull()
    expect(getPasswordStrength(validInput.password)).toBe(4)
  })

  it('rejects mismatched passwords and missing terms acceptance', () => {
    expect(validateRegistration({ ...validInput, confirmPassword: 'OtherPassword123!' })).toBe('Passwords do not match.')
    expect(validateRegistration({ ...validInput, termsAccepted: false })).toBe('Accept the terms to create an account.')
  })

  it('enforces length and character-class requirements', () => {
    expect(validateRegistration({ ...validInput, password: 'short', confirmPassword: 'short' })).toContain('12 characters')
    expect(getPasswordStrength('lowercaseonly')).toBe(1)
  })
})
