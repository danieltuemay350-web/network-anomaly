/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          900: '#0a0e17',
          800: '#111827',
          700: '#1e293b',
          600: '#334155',
          500: '#475569',
          400: '#64748b',
          300: '#94a3b8',
          accent: '#22d3ee',
          green: '#34d399',
          yellow: '#fbbf24',
          red: '#f87171',
          orange: '#fb923c',
        },
      },
    },
  },
  plugins: [],
  safelist: [
    // Severity badge classes (constructed dynamically from data)
    'severity-CRITICAL',
    'severity-HIGH',
    'severity-MEDIUM',
    'severity-LOW',
    'status-NEW',
    'status-ACKNOWLEDGED',
    'status-RESOLVED',
  ],
}
