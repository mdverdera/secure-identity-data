'use client';

/**
 * Authentication Context — in-memory state machine.
 *
 * Manages the complete OAuth + DPoP authentication lifecycle:
 *   Unauthenticated → Authenticating → Authenticated → SigningOut
 *   Any state → Error (on failure)
 *
 * Security decisions:
 * - Access token lives ONLY in React state (never localStorage).
 * - DPoP CryptoKeyPair lives alongside the token in the same state object.
 * - On logout/page-unload, state is cleared in memory — no persisted token.
 * - The private key is non-extractable — it cannot be exported even by XSS code.
 *
 * Limitation: token is lost on page refresh → user must re-authenticate.
 * This is intentional for a security-first POC. A production BFF architecture
 * would use HttpOnly cookies via a server-side proxy.
 */

import React, { createContext, useContext, useReducer, useCallback } from 'react';
import { buildAuthorizationUrl, exchangeCodeForToken, validateCallback, OAuthError, type CallbackParams, type TokenResponse } from '../lib/auth/oauth-flow';
import { generateDpopKeyPair } from '../lib/dpop/dpop-key';

// ─────────────────────────────────────────────────────────────────────────────
// State types
// ─────────────────────────────────────────────────────────────────────────────

export type AuthStatus =
  | 'unauthenticated'
  | 'authenticating'
  | 'authenticated'
  | 'error'
  | 'signing-out';

export interface AuthError {
  code: string;
  message: string;
}

export interface AuthenticatedState {
  status: 'authenticated';
  accessToken: string;
  tokenType: 'DPoP';
  expiresAt: Date;
  dpopKeyPair: CryptoKeyPair;
  scope: string;
}

export type AuthState =
  | { status: 'unauthenticated' }
  | { status: 'authenticating' }
  | AuthenticatedState
  | { status: 'error'; error: AuthError }
  | { status: 'signing-out' };

// ─────────────────────────────────────────────────────────────────────────────
// Actions
// ─────────────────────────────────────────────────────────────────────────────

type AuthAction =
  | { type: 'LOGIN_START' }
  | { type: 'LOGIN_SUCCESS'; payload: { accessToken: string; expiresIn: number; dpopKeyPair: CryptoKeyPair; scope: string } }
  | { type: 'LOGIN_ERROR'; payload: AuthError }
  | { type: 'LOGOUT' }
  | { type: 'CLEAR_ERROR' };

// ─────────────────────────────────────────────────────────────────────────────
// Reducer
// ─────────────────────────────────────────────────────────────────────────────

function authReducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case 'LOGIN_START':
      return { status: 'authenticating' };

    case 'LOGIN_SUCCESS': {
      const { accessToken, expiresIn, dpopKeyPair, scope } = action.payload;
      const expiresAt = new Date(Date.now() + expiresIn * 1000);
      return {
        status: 'authenticated',
        accessToken,
        tokenType: 'DPoP',
        expiresAt,
        dpopKeyPair,
        scope,
      };
    }

    case 'LOGIN_ERROR':
      return { status: 'error', error: action.payload };

    case 'LOGOUT':
    case 'CLEAR_ERROR':
      return { status: 'unauthenticated' };

    default:
      return state;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Context
// ─────────────────────────────────────────────────────────────────────────────

interface AuthContextValue {
  state: AuthState;
  /** Initiates the OAuth Authorization Code + PKCE flow. Redirects the browser. */
  login: () => Promise<void>;
  /** Handles the OAuth callback after the browser is redirected back. */
  handleCallback: (params: CallbackParams, dpopKeyPair: CryptoKeyPair) => Promise<void>;
  /** Clears all authentication state. */
  logout: () => void;
  /** Clears the error state. */
  clearError: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// ─────────────────────────────────────────────────────────────────────────────
// Provider
// ─────────────────────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(authReducer, { status: 'unauthenticated' });

  const login = useCallback(async () => {
    dispatch({ type: 'LOGIN_START' });
    try {
      const url = await buildAuthorizationUrl();
      window.location.href = url;
    } catch (err) {
      dispatch({
        type: 'LOGIN_ERROR',
        payload: {
          code: 'login_initiation_failed',
          message: err instanceof Error ? err.message : 'Failed to initiate login.',
        },
      });
    }
  }, []);

  const handleCallback = useCallback(
    async (params: CallbackParams, dpopKeyPair: CryptoKeyPair) => {
      dispatch({ type: 'LOGIN_START' });
      try {
        const { code, codeVerifier } = validateCallback(params);
        const tokenResponse: TokenResponse = await exchangeCodeForToken(code, codeVerifier, dpopKeyPair);

        dispatch({
          type: 'LOGIN_SUCCESS',
          payload: {
            accessToken: tokenResponse.access_token,
            expiresIn: tokenResponse.expires_in,
            dpopKeyPair,
            scope: tokenResponse.scope,
          },
        });
      } catch (err) {
        let code = 'authentication_failed';
        let message = 'Authentication failed. Please try signing in again.';

        if (err instanceof OAuthError) {
          code = err.code;
          message = err.message;
        } else if (err instanceof Error) {
          message = err.message;
        }

        dispatch({ type: 'LOGIN_ERROR', payload: { code, message } });
      }
    },
    [],
  );

  const logout = useCallback(() => {
    dispatch({ type: 'LOGOUT' });
  }, []);

  const clearError = useCallback(() => {
    dispatch({ type: 'CLEAR_ERROR' });
  }, []);

  return (
    <AuthContext.Provider value={{ state, login, handleCallback, logout, clearError }}>
      {children}
    </AuthContext.Provider>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook
// ─────────────────────────────────────────────────────────────────────────────

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

/** Type guard: returns true when the auth state is authenticated */
export function isAuthenticated(state: AuthState): state is AuthenticatedState {
  return state.status === 'authenticated';
}
