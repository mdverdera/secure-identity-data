import Link from 'next/link';

export default function HomePage() {
  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <div className="inline-block bg-[var(--surface)] border border-[var(--border)] rounded px-2 py-1 text-xs text-[var(--muted)] mb-3">
          Educational POC — Not for production use
        </div>
        <h1 className="text-2xl font-semibold text-[var(--text)] mb-2">
          Secure Identity &amp; Trusted Data
        </h1>
        <p className="text-[var(--muted)]">
          A browser-based demonstration of OAuth 2.1, PKCE, DPoP, and protected API access.
          All identity data is entirely fictional.
        </p>
      </div>

      {/* Sign in CTA */}
      <div className="mb-10">
        <Link
          href="/login"
          className="inline-block bg-[var(--accent)] text-white px-5 py-2.5 rounded text-sm font-medium hover:opacity-90 transition-opacity"
        >
          Sign in
        </Link>
      </div>

      {/* Architecture diagram */}
      <section className="mb-10">
        <h2 className="text-base font-semibold text-[var(--text)] mb-4">Architecture</h2>
        <div className="border border-[var(--border)] rounded bg-[var(--surface)] p-5 text-sm">
          <div className="flex flex-col gap-0 items-start font-mono text-[var(--text)]">
            <FlowStep label="Next.js Client" sub="Browser — EC P-256 key pair, PKCE" />
            <Arrow />
            <FlowStep label="OAuth Authorization" sub="Authorization Code + PKCE + state" />
            <Arrow />
            <FlowStep label="Identity Provider" sub="https://localhost:7001" />
            <Arrow />
            <FlowStep label="DPoP-bound Access Token" sub="cnf.jkt key binding, ES256 proof" />
            <Arrow />
            <FlowStep label="Identity Data API" sub="https://localhost:7100" />
            <Arrow />
            <FlowStep label="Protected Identity Data" sub="identity.read scope required" />
          </div>
        </div>
      </section>

      {/* Technology table */}
      <section className="mb-10">
        <h2 className="text-base font-semibold text-[var(--text)] mb-4">What is demonstrated</h2>
        <div className="border border-[var(--border)] rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-[var(--surface)] border-b border-[var(--border)]">
                <th className="text-left px-4 py-2.5 font-medium text-[var(--text)]">Standard / Technology</th>
                <th className="text-left px-4 py-2.5 font-medium text-[var(--text)]">Implementation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {FEATURES.map(({ standard, impl }) => (
                <tr key={standard} className="hover:bg-[var(--surface)] transition-colors">
                  <td className="px-4 py-2.5 text-[var(--text)]">{standard}</td>
                  <td className="px-4 py-2.5 text-[var(--muted)]">{impl}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Disclaimer */}
      <div className="border border-[var(--border)] rounded bg-[var(--surface)] px-4 py-3 text-sm text-[var(--muted)]">
        <strong className="text-[var(--text)]">Disclaimer:</strong> All user and identity data is entirely
        fictional test data. This project is not affiliated with any government identity service,
        Singpass, or MyInfo.
      </div>
    </div>
  );
}

function FlowStep({ label, sub }: { label: string; sub: string }) {
  return (
    <div className="border border-[var(--border)] rounded bg-white px-3 py-2 w-64">
      <div className="font-medium text-[var(--text)] text-xs">{label}</div>
      <div className="text-[var(--muted)] text-xs mt-0.5">{sub}</div>
    </div>
  );
}

function Arrow() {
  return (
    <div className="ml-8 text-[var(--muted)] text-lg leading-none py-0.5">│</div>
  );
}

const FEATURES = [
  { standard: 'OAuth 2.1 Authorization Code', impl: 'RFC 6749 / OAuth 2.1 draft' },
  { standard: 'PKCE S256', impl: 'RFC 7636 — code_challenge SHA-256' },
  { standard: 'JWT access tokens', impl: 'RS256, 15-minute TTL, jti, kid' },
  { standard: 'JWK / JWKS endpoint', impl: '/.well-known/jwks.json' },
  { standard: 'OpenID-style discovery', impl: '/.well-known/openid-configuration' },
  { standard: 'DPoP sender-constrained tokens', impl: 'RFC 9449 — EC P-256, ES256' },
  { standard: 'JWK Thumbprint', impl: 'RFC 7638 — cnf.jkt key binding' },
  { standard: 'DPoP replay protection', impl: 'jti uniqueness enforced server-side' },
  { standard: 'OAuth scope enforcement', impl: 'identity.read required' },
  { standard: 'ASP.NET Core Identity Provider', impl: '.NET 10, CQRS + MediatR' },
  { standard: 'Next.js Browser Client', impl: 'App Router, Web Crypto API' },
  { standard: 'PostgreSQL', impl: 'Identity data via Entity Framework Core' },
];
