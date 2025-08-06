import { Context, Next } from 'hono';
import { verifyAuth } from '@hono/auth-js';

/**
 * Middleware that ensures the user is authenticated before accessing
 * protected routes. It retrieves the current Auth.js session and validates
 * that a user is present. If authentication fails, the client is redirected
 * to the sign-in page with the original URL preserved in the callbackUrl
 * query parameter. On success, the session is attached to the context and
 * control is passed to the next handler.
 *
 * @param c - Hono Context; the session will be available at c.get('session')
 *            after validation.
 * @param next - Next function to call if authentication succeeds
 *
 * @remarks
 * - Must be used after setting up Auth.js session handling so that request
 *   cookies are parsed.
 * - Relies on verifyAuth() from @hono/auth-js.
 * - Redirects unauthenticated users to
 *   `/auth/signin?callbackUrl=<original URL>`.
 * - Original request URL is URL-encoded in callbackUrl.
 *
 * @example
 * ```ts
 * import { requireAuth } from './guards'
 *
 * app.get('/profile', requireAuth, (c) => {
 *   const session = c.get('session')
 *   return c.html(profileTemplate({ user: session.user }))
 * })
 * ```
 */
export async function requireAuth(
  c: Context,
  next: Next,
): Promise<Response | void> {
  const auth = verifyAuth();

  if (!auth) {
    const callbackUrl: string = encodeURIComponent(c.req.url);
    return c.redirect(`/auth/signin?callbackUrl=${callbackUrl}`);
  }

  c.set('session', auth);
  await next();
}
