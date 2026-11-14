import { defineConfig, type UserConfig } from 'vite'
import react from '@vitejs/plugin-react'
import type { InlineConfig } from 'vitest'

const config = {
  plugins: [react()],
  server: { host: '0.0.0.0', port: 5174, strictPort: true },
  test: { environment: 'jsdom' }
} satisfies UserConfig & { test: InlineConfig }

export default defineConfig(config)