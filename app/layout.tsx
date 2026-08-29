import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'System Guard — SSH Log Analyzer',
  description: 'Lokalna analiza logów SSH dla administratorów Linuxa.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="pl">
      <body>{children}</body>
    </html>
  );
}
