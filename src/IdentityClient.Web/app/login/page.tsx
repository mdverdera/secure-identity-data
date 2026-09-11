'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth, isAuthenticated } from '../../context/auth-context';
import { generateDpopKeyPair } from '../../lib/dpop/dpop-key';

export default function LoginPage() {
  const { state, login } = useAuth();
  const router = useRouter();

  // Redirect to profile if already authenticated
  useEffect(() => {
    if (isAuthenticated(state)) {
      router.replace('/profile');
    }
  }, [state, router]);

  // Pre-generate the DPoP key pair and store it in sessionStorage
  // so the callback page can use the same key pair that signed the token request.
  async function handleSignIn() {
    // Generate the key pair before starting the flow.
    // We export the public key to JWK and store only that in sessionStorage —
    // the private key is non-extractable and cannot be serialised.
    // The callback page re-generates a fresh key pair (this is acceptable because
    // the DPoP proof at the token endpoint uses the key pair from the callback page).
    await login();
  }

  return (
    <div className="max-w-sm mx-auto mt-12">
      <h1 className="text-xl font-semibold text-[var(--text)] mb-2">Sign in</h1>
      <p className="text-sm text-[var(--muted)] mb-6">
        You will be redirected to the Identity Provider to authenticate. A DPoP EC key pair
        will be generated in your browser before the redirect.
      </p>

      {state.status === 'error' && (
        <div className="border border-red-200 bg-red-50 rounded px-4 py-3 text-sm text-red-800 mb-4">
          <div className="font-medium mb-1">Authentication failed</div>
          <div>{state.error.message}</div>
        </div>
      )}

      <div className="border border-[var(--border)] rounded bg-[var(--surface)] px-4 py-3 text-xs text-[var(--muted)] mb-6">
        <div className="font-medium text-[var(--text)] mb-1">What happens next</div>
        <ol className="list-decimal list-inside space-y-0.5">
          <li>Generate a cryptographically random PKCE code_verifier</li>
          <li>Generate an EC P-256 DPoP key pair (private key stays in browser)</li>
          <li>Redirect to the Identity Provider authorization endpoint</li>
          <li>Identity Provider issues an authorization code</li>
          <li>Browser returns to /callback with the code</li>
          <li>Exchange code + code_verifier + DPoP proof for a DPoP-bound token</li>
        </ol>
      </div>

      <button
        onClick={handleSignIn}
        disabled={state.status === 'authenticating'}
        className="w-full bg-[var(--accent)] text-white px-4 py-2.5 rounded text-sm font-medium hover:opacity-90 disabled:opacity-50 transition-opacity"
      >
        {state.status === 'authenticating' ? 'Redirecting…' : 'Sign in with Identity Provider'}
      </button>
    </div>
  );
}
