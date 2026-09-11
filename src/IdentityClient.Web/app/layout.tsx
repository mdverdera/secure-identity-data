import type { Metadata } from 'next';
import './globals.css';
import { AuthProvider } from '../context/auth-context';
import { Nav } from '../components/Nav';

export const metadata: Metadata = {
  title: 'Secure Identity & Trusted Data POC',
  description: 'Browser-based OAuth Authorization Code + PKCE + DPoP demonstration',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <Nav />
          <main className="max-w-3xl mx-auto px-4 py-8">
            {children}
          </main>
        </AuthProvider>
      </body>
    </html>
  );
}
