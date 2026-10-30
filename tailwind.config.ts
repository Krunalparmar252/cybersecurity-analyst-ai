import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        canvas: {
          DEFAULT: '#0A0B0D',
          light: '#F8F9FA',
        },
        surface: {
          DEFAULT: '#111317',
          subtle: '#181B20',
          elevated: '#1F232B',
          light: '#FFFFFF',
          'light-subtle': '#F1F3F5',
        },
        line: {
          DEFAULT: 'rgba(255, 255, 255, 0.08)',
          strong: 'rgba(255, 255, 255, 0.16)',
          light: 'rgba(0, 0, 0, 0.08)',
          'light-strong': 'rgba(0, 0, 0, 0.16)',
        },
        text: {
          primary: '#E8EAED',
          secondary: '#9BA1A6',
          muted: '#5F6368',
          'light-primary': '#1A1D20',
          'light-secondary': '#5F6368',
          'light-muted': '#80868B',
        },
        signal: {
          DEFAULT: '#C6FF3D',
          hover: '#B5F228',
          dim: 'rgba(198, 255, 61, 0.12)',
          dark: '#1B2E05',
        },
        severity: {
          critical: '#FF4D4D',
          high: '#FF9F43',
          medium: '#F5D547',
          low: '#5BC0FF',
        },
      },
      fontFamily: {
        sans: ['var(--font-geist-sans)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-geist-mono)', 'monospace'],
        serif: ['var(--font-instrument-serif)', 'serif'],
      },
      animation: {
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
};

export default config;

