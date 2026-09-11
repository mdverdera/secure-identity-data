'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth, isAuthenticated } from '../../context/auth-context';
import { getProfile, type ProfileResult } from '../../lib/api/identity-api';
import { ApiError } from '../../lib/api/api-client';

type LoadState = { status: 'loading' } | { status: 'success'; data: ProfileResult } | { status: 'error'; message: string };

export default function ProfilePage() {
  const { state } = useAuth();
  const router = useRouter();
  const [load, setLoad] = useState<LoadState>({ status: 'loading' });

  useEffect(() => {
    if (!isAuthenticated(state)) {
      router.replace('/login');
      return;
    }

    getProfile({ accessToken: state.accessToken, dpopKeyPair: state.dpopKeyPair })
      .then((data) => setLoad({ status: 'success', data }))
      .catch((err) => {
        const message = err instanceof ApiError
          ? err.message
          : err instanceof Error ? err.message : 'Failed to load profile.';
        setLoad({ status: 'error', message });
      });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (!isAuthenticated(state)) return null;

  return (
    <div>
      <h1 className="text-xl font-semibold text-[var(--text)] mb-1">Profile</h1>
      <p className="text-sm text-[var(--muted)] mb-6">
        Retrieved from <code className="text-xs bg-[var(--surface)] px-1 py-0.5 rounded">GET /api/profile</code> using a DPoP-bound access token.
      </p>

      {load.status === 'loading' && (
        <div className="text-sm text-[var(--muted)]">Loading profile…</div>
      )}

      {load.status === 'error' && (
        <div className="border border-red-200 bg-red-50 rounded px-4 py-3 text-sm text-red-800">
          <div className="font-medium mb-1">Failed to load profile</div>
          <div>{load.message}</div>
        </div>
      )}

      {load.status === 'success' && (
        <div className="border border-[var(--border)] rounded overflow-hidden">
          <div className="bg-[var(--surface)] border-b border-[var(--border)] px-4 py-2.5 text-xs font-medium text-[var(--muted)] uppercase tracking-wide">
            User Profile — Fictional Test Data
          </div>
          <div className="divide-y divide-[var(--border)]">
            <DataRow label="User ID" value={load.data.userId} />
            <DataRow label="Full Name" value={load.data.fullName} />
            <DataRow label="Email" value={load.data.email} />
          </div>
        </div>
      )}

      {load.status === 'success' && (
        <div className="mt-4 border border-[var(--border)] rounded bg-[var(--surface)] px-4 py-3 text-xs text-[var(--muted)]">
          <div className="font-medium text-[var(--text)] mb-1">How this request was authenticated</div>
          <div className="space-y-0.5">
            <div><span className="font-mono">Authorization: DPoP &lt;access-token&gt;</span></div>
            <div><span className="font-mono">DPoP: &lt;fresh ES256 proof, htm=GET, htu=.../api/profile, ath=SHA256(token)&gt;</span></div>
          </div>
        </div>
      )}
    </div>
  );
}

function DataRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex px-4 py-3 text-sm">
      <span className="w-32 text-[var(--muted)] shrink-0">{label}</span>
      <span className="text-[var(--text)]">{value}</span>
    </div>
  );
}
