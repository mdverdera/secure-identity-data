'use client';

import Link from 'next/link';
import { useAuth, isAuthenticated } from '../context/auth-context';

export function Nav() {
  const { state, logout } = useAuth();
  const authed = isAuthenticated(state);

  return (
    <nav className="border-b border-[var(--border)] bg-white sticky top-0 z-10">
      <div className="max-w-3xl mx-auto px-4 py-3 flex items-center justify-between">
        <Link href="/" className="font-semibold text-[var(--text)] hover:text-[var(--accent)] transition-colors">
          Secure Identity POC
        </Link>
        <div className="flex items-center gap-5 text-sm">
          {authed && (
            <>
              <Link href="/profile" className="text-[var(--muted)] hover:text-[var(--text)] transition-colors">
                Profile
              </Link>
              <Link href="/identity" className="text-[var(--muted)] hover:text-[var(--text)] transition-colors">
                Identity
              </Link>
              <Link href="/security" className="text-[var(--muted)] hover:text-[var(--text)] transition-colors">
                Security
              </Link>
              <button
                onClick={logout}
                className="text-[var(--muted)] hover:text-[var(--danger)] transition-colors"
              >
                Sign out
              </button>
            </>
          )}
          {!authed && (
            <Link href="/login" className="text-[var(--accent)] font-medium hover:underline">
              Sign in
            </Link>
          )}
        </div>
      </div>
    </nav>
  );
}
