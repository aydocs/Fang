/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        fang: {
          900: '#0a0a0f',
          800: '#12121a',
          700: '#1a1a2e',
          600: '#16213e',
          500: '#0f3460',
          400: '#1a5276',
          300: '#2980b9',
          200: '#5dade2',
          100: '#aed6f1',
        },
      },
    },
  },
  plugins: [],
}
