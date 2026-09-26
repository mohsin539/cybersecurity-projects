/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: { 950: '#050810', 900: '#0a0f1c', 800: '#101828', 700: '#1b2437' },
        accent: { DEFAULT: '#22d3ee', dim: '#0e7490' },
        danger: '#f43f5e', warn: '#f59e0b', ok: '#34d399', vip: '#a78bfa'
      },
      boxShadow: {
        glow: '0 0 24px rgba(34,211,238,0.15)'
      }
    },
  },
  plugins: [],
}
