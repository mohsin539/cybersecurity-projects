import { defineConfig } from 'vite'

export default defineConfig({
  base: './',
  build: {
    target: 'es2022',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          three: ['three'],
          vendor: ['zustand', 'd3-scale'],
        },
      },
    },
  },
  server: { port: 5173 },
  test: { environment: 'node', include: ['tests/**/*.test.ts'] },
})
