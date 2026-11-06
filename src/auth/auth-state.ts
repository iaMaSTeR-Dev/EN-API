/**
 * Explicit Authentication State Machine for Bank Eghtesad Novin API Client.
 * Enforces valid state transitions and maintains an audit history of state changes.
 */

export type AuthenticationState =
  | 'UNAUTHENTICATED'
  | 'AUTHENTICATING'
  | 'OTP_REQUIRED'
  | 'CAPTCHA_REQUIRED'
  | 'AUTHENTICATED'
  | 'REFRESHING'
  | 'EXPIRED'
  | 'INVALID'
  | 'LOGGED_OUT';

export interface StateTransitionRecord {
  from: AuthenticationState;
  to: AuthenticationState;
  timestamp: number;
  reason?: string;
}

/**
 * Valid state transition matrix.
 * Disallows impossible or contradictory transitions (e.g. LOGGED_OUT -> AUTHENTICATED directly).
 */
const VALID_TRANSITIONS: Record<AuthenticationState, Set<AuthenticationState>> = {
  UNAUTHENTICATED: new Set(['AUTHENTICATING', 'EXPIRED', 'INVALID', 'AUTHENTICATED', 'LOGGED_OUT']),
  AUTHENTICATING: new Set(['AUTHENTICATED', 'OTP_REQUIRED', 'CAPTCHA_REQUIRED', 'UNAUTHENTICATED', 'INVALID', 'LOGGED_OUT']),
  OTP_REQUIRED: new Set(['AUTHENTICATING', 'UNAUTHENTICATED', 'INVALID', 'LOGGED_OUT']),
  CAPTCHA_REQUIRED: new Set(['AUTHENTICATING', 'UNAUTHENTICATED', 'INVALID', 'LOGGED_OUT']),
  AUTHENTICATED: new Set(['REFRESHING', 'EXPIRED', 'INVALID', 'LOGGED_OUT', 'AUTHENTICATING']),
  REFRESHING: new Set(['AUTHENTICATED', 'EXPIRED', 'INVALID', 'LOGGED_OUT']),
  EXPIRED: new Set(['REFRESHING', 'AUTHENTICATING', 'UNAUTHENTICATED', 'INVALID', 'LOGGED_OUT']),
  INVALID: new Set(['AUTHENTICATING', 'UNAUTHENTICATED', 'LOGGED_OUT']),
  LOGGED_OUT: new Set(['AUTHENTICATING', 'UNAUTHENTICATED']),
};

export class AuthStateManager {
  private currentState: AuthenticationState;
  private history: StateTransitionRecord[] = [];
  private readonly maxHistoryLength: number = 50;

  constructor(initialState: AuthenticationState = 'UNAUTHENTICATED') {
    this.currentState = initialState;
    this.recordTransition(initialState, initialState, 'Initial state');
  }

  getState(): AuthenticationState {
    return this.currentState;
  }

  canTransitionTo(nextState: AuthenticationState): boolean {
    if (this.currentState === nextState) return true;
    const allowed = VALID_TRANSITIONS[this.currentState];
    return allowed ? allowed.has(nextState) : false;
  }

  transitionTo(nextState: AuthenticationState, reason?: string): void {
    if (this.currentState === nextState) return;

    if (!this.canTransitionTo(nextState)) {
      throw new Error(
        `Invalid authentication state transition from ${this.currentState} to ${nextState}${reason ? ` (${reason})` : ''}`
      );
    }

    const from = this.currentState;
    this.currentState = nextState;
    this.recordTransition(from, nextState, reason);
  }

  private recordTransition(from: AuthenticationState, to: AuthenticationState, reason?: string): void {
    this.history.push({
      from,
      to,
      timestamp: Date.now(),
      reason,
    });
    if (this.history.length > this.maxHistoryLength) {
      this.history.shift();
    }
  }

  getHistory(): ReadonlyArray<StateTransitionRecord> {
    return [...this.history];
  }

  reset(initialState: AuthenticationState = 'UNAUTHENTICATED', reason?: string): void {
    const from = this.currentState;
    this.currentState = initialState;
    this.recordTransition(from, initialState, reason || 'Reset');
  }
}

