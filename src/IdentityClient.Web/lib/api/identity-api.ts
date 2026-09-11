/**
 * Identity Data API client functions.
 * Wraps the DPoP-authenticated calls to /api/profile and /api/identity.
 */

import { dpopFetch, type DpopSession } from './api-client';
import { endpoints } from '../auth/auth-config';

// ─────────────────────────────────────────────────────────────────────────────
// Response types (matching IdentityData.Api response models)
// ─────────────────────────────────────────────────────────────────────────────

export interface ProfileResult {
  userId: string;
  fullName: string;
  email: string;
}

export type Sensitivity = 'Public' | 'Internal' | 'Confidential' | 'Restricted';

export interface IdentityAttributeResult {
  name: string;
  value: string;
  sensitivity: Sensitivity;
}

// ─────────────────────────────────────────────────────────────────────────────
// API calls
// ─────────────────────────────────────────────────────────────────────────────

/**
 * GET /api/profile
 * Returns the authenticated user's basic profile.
 * Requires a DPoP-bound access token with identity.read scope.
 */
export async function getProfile(session: DpopSession): Promise<ProfileResult> {
  return dpopFetch<ProfileResult>(endpoints.profile, session, 'GET');
}

/**
 * GET /api/identity
 * Returns the authenticated user's identity attributes with sensitivity labels.
 * Requires a DPoP-bound access token with identity.read scope.
 * All data is fictional test data.
 */
export async function getIdentityAttributes(session: DpopSession): Promise<IdentityAttributeResult[]> {
  return dpopFetch<IdentityAttributeResult[]>(endpoints.identity, session, 'GET');
}
