'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth, isAuthenticated } from '../../context/auth-context';
import { getIdentityAttributes, type IdentityAttributeResult, type Sensitivity } from '../../lib/api/identity-api';
import { ApiError } from '../../lib/api/api-client';

type LoadState =
  | { status: 'loading' }
  | { status: 'success'; data: IdentityAttributeResult[] }
  | { status: 'error'; message: string };

const SENSITIVITY_STYLE: Record<Sensitivity, string> = {
  Public: 'bg-green-50 text-green-800 border-green-200',
  Internal: 'bg-blue-50 text-blue-800 border-blue-200',
  Confidential: 'bg-amber-50 text-amber-800 border-amber-200',
  Restricted: 'bg-red-50 text-red-800 border-red-200',
};

export default function IdentityPage() {
  const { state } = useAuth();
  const router = useRouter();
  const [load, setLoad] = useState<LoadState>({ status: 'loading' });

  useEffect(() => {
    if (!isAuthenticated(state)) {
      router.replace('/login');
      return;
    }

    getIdentityAttributes({ accessToken: state.accessToken, dpopKeyPair: state.dpopKeyPair })
      .then((data) => setLoad({ status: 'success', data }))
      .catch((err) => {
        const message = err instanceof ApiError
          ? err.message
          : err instanceof Error ? err.message : 'Failed to load identity attributes.';
        setLoad({ status: 'error', message });
      });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (!isAuthenticated(state)) return null;

  return (
    <div>
      <h1 className="text-xl font-semibold text-[var(--text)] mb-1">Identity Attributes</h1>
      <p className="text-sm text-[var(--muted)] mb-1">
        Retrieved from <code className="text-xs bg-[var(--surface)] px-1 py-0.5 rounded">GET /api/identity</code> using a DPoP-bound access token.
      </p>
      <div className="inline-block bg-amber-50 border border-amber-200 text-amber-800 text-xs rounded px-2 py-0.5 mb-6">
        All data shown is entirely fictional test data
      </div>

      {load.status === 'loading' && (
        <div className="text-sm text-[var(--muted)]">Loading identity attributes…</div>
      )}

      {load.status === 'error' && (
        <div className="border border-red-200 bg-red-50 rounded px-4 py-3 text-sm text-red-800">
          <div className="font-medium mb-1">Failed to load identity attributes</div>
          <div>{load.message}</div>
        </div>
      )}

      {load.status === 'success' && (
        <>
          <div className="border border-[var(--border)] rounded overflow-hidden mb-4">
            <div className="bg-[var(--surface)] border-b border-[var(--border)] px-4 py-2.5 text-xs font-medium text-[var(--muted)] uppercase tracking-wide">
              Identity Attributes — Fictional Test Data
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-[var(--surface)] border-b border-[var(--border)]">
                  <th className="text-left px-4 py-2 font-medium text-[var(--muted)]">Attribute</th>
                  <th className="text-left px-4 py-2 font-medium text-[var(--muted)]">Value</th>
                  <th className="text-left px-4 py-2 font-medium text-[var(--muted)]">Sensitivity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {load.data.map((attr) => (
                  <tr key={attr.name} className="hover:bg-[var(--surface)] transition-colors">
                    <td className="px-4 py-2.5 text-[var(--muted)]">{attr.name}</td>
                    <td className="px-4 py-2.5 text-[var(--text)]">{attr.value}</td>
                    <td className="px-4 py-2.5">
                      <span className={`inline-block border rounded px-1.5 py-0.5 text-xs font-medium ${SENSITIVITY_STYLE[attr.sensitivity] ?? 'bg-gray-50 text-gray-800 border-gray-200'}`}>
                        {attr.sensitivity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="border border-[var(--border)] rounded bg-[var(--surface)] px-4 py-3 text-xs text-[var(--muted)]">
            <div className="font-medium text-[var(--text)] mb-1">Scope enforcement</div>
            <div>This endpoint requires the <code className="font-mono">identity.read</code> scope.
            Requests without this scope are rejected with HTTP 403.</div>
          </div>
        </>
      )}
    </div>
  );
}
