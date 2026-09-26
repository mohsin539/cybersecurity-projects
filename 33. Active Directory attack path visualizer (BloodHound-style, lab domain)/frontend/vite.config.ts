import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Lab dev server proxies /api to FastAPI; production build is copied into
// backend/static and served same-origin by FastAPI (no CORS, CSP-friendly).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': 'http://localhost:8000' },
  },
  build: {
    outDir: '../backend/static',
    emptyOutDir: true,
  },
})
