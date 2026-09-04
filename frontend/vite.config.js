import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/scan': 'http://localhost:4000',
      '/history': 'http://localhost:4000',
      '/projects': 'http://localhost:4000',
      '/health': 'http://localhost:4000',
      '/auth/github/session': 'http://localhost:4000',
      '/auth/github/user': 'http://localhost:4000',
      '/auth/github/logout': 'http://localhost:4000',
      '/auth/github/status': 'http://localhost:4000',
      '/github': 'http://localhost:4000',
      '/validate-repo': 'http://localhost:4000',
    },
  },
})
