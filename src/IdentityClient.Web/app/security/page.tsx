'use client';

/**
 * Security page — shows how the security mechanism works.
 *
 * Displays ONLY non-sensitive information:
 *   - Authentication method, flow parameters, DPoP algorithm, scope
 *   - Safe JWT claims (sub, iat, exp, scope) decoded from the access token
 *
 * NEVER displays:
 *   - Private key material (it's non-extractable anyway)
 *   - Raw access token string
 *   - DPoP proof content (it's ephemeral)
 *   - Any secret or credential
 */

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth, isAuthenticated } from '../../context/auth-context';
import { computeJwkThumbprint } from '../../lib/dpop/jwk-thumbprint';
import { exportPublicKeyAsJwk } from '../../lib/dpop/dpop-key';
import { authConfig } from '../../lib/auth/auth-config';

interface SafeTokenClaims {
  sub?: string;
  iat?: number;
  exp?: number;
  scope?: string;
  jti?: string;
  iss?: string;
  aud?: string;
}

function decodeSafeClaims(accessToken: string): SafeTokenClaims {
  try {
    const parts = accessToken.split('.');
    if (parts.length !== 3) return {};
    const pad = parts[1].length % 4 === 0 ? '' : '='.repeat(4 - (parts[1].length % 4));
    const json = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/') + pad);
    const all = JSON.parse(json);
    // Return only safe, non-sensitive claims
    return {
      sub: typeof all.sub === 'string' ? all.sub : undefined,
      iat: typeof all.iat === 'number' ? all.iat : undefined,
      exp: typeof all.exp === 'number' ? all.exp : undefined,
      scope: typeof all.scope === 'string' ? all.scope : undefined,
      jti: typeof all.jti === 'string' ? all.jti : undefined,
      iss: typeof all.iss === 'string' ? all.iss : undefined,
      aud: typeof all.aud === 'string' ? all.aud : undefined,
    };
  } catch {
    return {};
  }
}

function formatUnix(unix?: number): string {
  if (!unix) return '—';
  return new Date(unix * 1000).toISOString();
}

export default function SecurityPage() {
  const { state } = useAuth();
  const router = useRouter();
  const [thumbprint, setThumbprint] = useState<string | null>(null);
  const [publicJwkShort, setPublicJwkShort] = useState<string | null>(null);

  useEffect(() => {
    if (!isAuthenticated(state)) {
      router.replace('/login');
      return;
    }

    // Derive non-sensitive info from the DPoP key pair
    exportPublicKeyAsJwk(state.dpopKeyPair.publicKey).then(async (jwk) => {
      const tp = await computeJwkThumbprint(jwk);
      setThumbprint(tp);
      setPublicJwkShort(`{"kty":"${jwk.kty}","crv":"${jwk.crv}","x":"${jwk.x?.slice(0, 8)}...","y":"${jwk.y?.slice(0, 8)}..."}`);
    });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (!isAuthenticated(state)) return null;

  const claims = decodeSafeClaims(state.accessToken);
  const expiresAt = state.expiresAt.toISOString();
  const expiresIn = Math.max(0, Math.round((state.expiresAt.getTime() - Date.now()) / 1000));

  return (
    <div>
      <h1 className="text-xl font-semibold text-[var(--text)] mb-1">Security Details</h1>
      <p className="text-sm text-[var(--muted)] mb-6">
        Non-sensitive security mechanism overview. Private key material is never displayed.
      </p>

      {/* OAuth / Token section */}
      <Section title="OAuth & Token">
        <InfoRow label="Flow" value="Authorization Code" />
        <InfoRow label="PKCE Method" value="S256 (SHA-256)" />
        <InfoRow label="Token Type" value={state.tokenType} />
        <InfoRow label="Scope" value={state.scope} />
        <InfoRow label="Client ID" value={authConfig.clientId} />
        <InfoRow label="Client Secret" value="None — public client" />
        <InfoRow label="Expires At" value={expiresAt} />
        <InfoRow label="Expires In" value={`${expiresIn}s`} />
      </Section>

      {/* DPoP section */}
      <Section title="DPoP (RFC 9449)">
        <InfoRow label="Algorithm" value="ES256" />
        <InfoRow label="Curve" value="P-256 (NIST / secp256r1)" />
        <InfoRow label="Key Storage" value="In-memory CryptoKey (non-extractable)" />
        <InfoRow label="Private Key Exported" value="Never — non-extractable flag set" />
        {thumbprint && <InfoRow label="cnf.jkt (Key Thumbprint)" value={thumbprint} mono />}
        {publicJwkShort && <InfoRow label="Public Key (JWK excerpt)" value={publicJwkShort} mono />}
      </Section>

      {/* JWT Claims section */}
      <Section title="Access Token Claims (safe subset)">
        <InfoRow label="sub" value={claims.sub ?? '—'} mono />
        <InfoRow label="iss" value={claims.iss ?? '—'} mono />
        <InfoRow label="aud" value={claims.aud ?? '—'} mono />
        <InfoRow label="scope" value={claims.scope ?? '—'} mono />
        <InfoRow label="jti" value={claims.jti ?? '—'} mono />
        <InfoRow label="iat" value={formatUnix(claims.iat)} />
        <InfoRow label="exp" value={formatUnix(claims.exp)} />
      </Section>

      {/* Security notes */}
      <Section title="Security Notes">
        <div className="px-4 py-3 text-sm text-[var(--muted)] space-y-1.5">
          <p>The access token is held <strong className="text-[var(--text)]">only in React state</strong> — it is never written to localStorage.</p>
          <p>The DPoP private key is <strong className="text-[var(--text)]">non-extractable</strong> — the Web Crypto API prevents any code from reading the raw bytes.</p>
          <p>A fresh DPoP proof is generated for <strong className="text-[var(--text)]">every API request</strong>. Proofs are not reused.</p>
          <p>The server tracks DPoP proof JTIs to prevent <strong className="text-[var(--text)]">replay attacks</strong>.</p>
          <p>Presenting the access token under the Bearer scheme is <strong className="text-[var(--text)]">rejected server-side</strong> — cnf.jkt binding is enforced.</p>
          <p>The OAuth state parameter protects against <strong className="text-[var(--text)]">CSRF attacks</strong> in the authorization redirect.</p>
        </div>
      </Section>

      <div className="text-xs text-[var(--muted)] mt-4">
        Token and key state are cleared on page refresh — re-authentication is required.
        This is intentional for a security-first POC.
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border border-[var(--border)] rounded overflow-hidden mb-4">
      <div className="bg-[var(--surface)] border-b border-[var(--border)] px-4 py-2.5 text-xs font-medium text-[var(--muted)] uppercase tracking-wide">
        {title}
      </div>
      <div className="divide-y divide-[var(--border)]">{children}</div>
    </div>
  );
}

function InfoRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex px-4 py-2.5 text-sm">
      <span className="w-44 text-[var(--muted)] shrink-0 text-xs pt-0.5">{label}</span>
      <span className={`text-[var(--text)] break-all ${mono ? 'font-mono text-xs' : ''}`}>{value}</span>
    </div>
  );
}
