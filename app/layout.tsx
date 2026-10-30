import type { Metadata } from 'next';
import { GeistSans } from 'geist/font/sans';
import { GeistMono } from 'geist/font/mono';
import { Instrument_Serif } from 'next/font/google';
import '@/styles/globals.css';

const instrumentSerif = Instrument_Serif({
  variable: '--font-instrument-serif',
  weight: ['400'],
  style: ['normal', 'italic'],
  subsets: ['latin'],
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'Autonomous Cybersecurity Analyst AI | Precision Security Instrument',
  description:
    'Ingests code/logs, detects vulnerabilities with deterministic AST pattern engine, then confirms, scores, explains, and patches via isolated sandbox verification.',
  keywords: [
    'cybersecurity',
    'AI analyst',
    'AST taint analysis',
    'automated vulnerability repair',
    'LangGraph',
    'Tree-sitter',
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`dark ${GeistSans.variable} ${GeistMono.variable} ${instrumentSerif.variable}`}
    >
      <body className="bg-canvas text-text-primary antialiased min-h-screen selection:bg-signal selection:text-canvas">
        {children}
      </body>
    </html>
  );
}
