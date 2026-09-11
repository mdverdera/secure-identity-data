'use client';

/**
 * OAuth Callback Page
 *
 * Handles the browser redirect from the Identity Provider after authorization.
 * Wrapped in Suspense because useSearchParams() requires it in Next.js App Router.
 */

import { Suspense, useEffect, useRef } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth, isAuthenticated } from '../../context/auth-context';
import { generateDpopKeyPair } from '../../lib/dpop/dpop-key';

function CallbackInner() {
  const { state, handleCallback, clearError } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const processed = useRef(false);

  useEffect(() => {
    // Guard: only process once (React StrictMode double-invokes effects in dev)
    if (processed.current) return;
    processed.current = true;

    async function processCallback() {
      const code = searchParams.get('code');
      const callbackState = searchParams.get('state');
      const error = searchParams.get('error');
      const errorDescription = searchParams.get('error_description');

      // Generate a fresh DPoP key pair for this session.
      // This key pair will sign the token endpoint request and all subsequent
      // resource server requests. The private key is non-extractable.
      const dpopKeyPair = await generateDpopKeyPair();

      await handleCallback(
        { code, state: callbackState, error, error_description: errorDescription },
        dpopKeyPair,
      );
    }

    processCallback();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Redirect on success
  useEffect(() => {
    if (isAuthenticated(state)) {
      router.replace('/profile');
    }
  }, [state, router]);

  if (state.status === 'error') {
    return (
      <div className="max-w-sm mx-auto mt-12">
        <h1 className="text-xl font-semibold text-[var(--text)] mb-4">Authentication failed</h1>
        <div className="border border-red-200 bg-red-50 rounded px-4 py-3 text-sm text-red-800 mb-4">
          <div className="font-medium mb-1">{friendlyErrorTitle(state.error.code)}</div>
          <div className="text-red-700">{state.error.message}</div>
        </div>
        <p className="text-sm text-[var(--muted)] mb-4">
          The authorization request could not be completed. This may be caused by:
        </p>
        <ul className="text-sm text-[var(--muted)] list-disc list-inside space-y-1 mb-6">
          <li>A state parameter mismatch (possible CSRF)</li>
          <li>An expired authorization session</li>
          <li>A rejected authorization request</li>
          <li>A network error during token exchange</li>
        </ul>
        <button
          onClick={() => { clearError(); router.replace('/login'); }}
          className="bg-[var(--accent)] text-white px-4 py-2 rounded text-sm font-medium hover:opacity-90"
        >
          Try again
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-sm mx-auto mt-12 text-center">
      <div className="text-[var(--muted)] text-sm mb-2">Completing sign in…</div>
      <div className="text-xs text-[var(--muted)]">
        Validating state, exchanging code, generating DPoP proof
      </div>
    </div>
  );
}

function friendlyErrorTitle(code: string): string {
  const titles: Record<string, string> = {
    state_mismatch: 'State mismatch — possible CSRF',
    invalid_state: 'No active authorization session',
    invalid_grant: 'Authorization code rejected',
    invalid_dpop_proof: 'DPoP proof invalid',
    access_denied: 'Access denied',
    missing_code: 'Missing authorization code',
  };
  return titles[code] ?? 'Authentication error';
}

export default function CallbackPage() {
  return (
    <Suspense fallback={
      <div className="max-w-sm mx-auto mt-12 text-center text-sm text-[var(--muted)]">
        Loading…
      </div>
    }>
      <CallbackInner />
    </Suspense>
  );
}
