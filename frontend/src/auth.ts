export function getPasswordStrength(password: string): number {
  return [
    password.length >= 12,
    /[a-z]/.test(password) && /[A-Z]/.test(password),
    /\d/.test(password),
    /[^A-Za-z0-9]/.test(password),
  ].filter(Boolean).length
}

export function validateRegistration(input: {
  fullName: string
  email: string
  password: string
  confirmPassword: string
  termsAccepted: boolean
}): string | null {
  if (input.fullName.trim().length < 2) return 'Enter your full name.'
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.email.trim())) return 'Enter a valid email address.'
  if (
    input.password.length < 12 ||
    !/[a-z]/.test(input.password) ||
    !/[A-Z]/.test(input.password) ||
    !/\d/.test(input.password)
  ) {
    return 'Use at least 12 characters with uppercase, lowercase, and a number.'
  }
  if (input.password !== input.confirmPassword) return 'Passwords do not match.'
  if (!input.termsAccepted) return 'Accept the terms to create an account.'
  return null
}
