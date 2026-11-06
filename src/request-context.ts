import { AsyncLocalStorage } from 'node:async_hooks';
import type { RequestContext } from './types.ts';

/**
 * Asynchronous Local Storage mechanism that provides request-scoped context
 * across asynchronous execution branches within the daemon process without
 * introducing global mutable state or relying on timestamp comparisons.
 */
export const requestContextStorage = new AsyncLocalStorage<RequestContext>();

/**
 * Executes a function within the scope of a given RequestContext.
 */
export function runWithRequestContext<T>(context: RequestContext, fn: () => T): T {
  return requestContextStorage.run(context, fn);
}

/**
 * Retrieves the currently active RequestContext for this asynchronous execution branch.
 * Returns undefined if invoked outside an active request scope (e.g. background maintenance or direct unit test).
 */
export function getRequestContext(): RequestContext | undefined {
  return requestContextStorage.getStore();
}

/**
 * Marks the active (or explicitly supplied) RequestContext as having initiated or
 * awaited a successful session renewal.
 *
 * @param expiredLocally True if the renewal was triggered by local session expiration;
 *                       false if triggered by remote bank rejection (e.g. Bank Code 3071).
 * @param explicitContext Optional RequestContext to mark directly if passed down explicitly.
 */
export function recordRequestContextRenewal(expiredLocally: boolean, explicitContext?: RequestContext): void {
  const target = explicitContext || requestContextStorage.getStore();
  if (target) {
    target.renewal = {
      renewed: true,
      expiredLocally,
    };
  }
}

