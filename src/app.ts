import type { Context } from 'hono';
import { Hono } from 'hono';
import { serveStatic } from '@hono/node-server/serve-static';
import { getCookie, setCookie } from 'hono/cookie';
import type { AuthUser } from '@hono/auth-js';
import { authHandler, getAuthUser, initAuthConfig } from '@hono/auth-js';
import config from './config.js';
import { getMessage } from './auth/message.js';
import { authConfig, buildLogoutUrl } from './auth/index.js';
import { requireAuth } from './auth/guard.js';
import { viewMiddleware } from './middleware/hbs.js';

interface Provider {
  id: string;
  name: string;
  signinUrl: string;
}

/**
 * Creates and configures the Hono application with all routes and middleware.
 *
 * @returns Promise resolving to the configured Hono application instance
 */
export async function build(): Promise<Hono> {
  const app: Hono = new Hono();

  app.use(
    '*',
    initAuthConfig(() => authConfig),
  );

  app.use(
    '/static/*',
    serveStatic({
      root: './public',
      rewriteRequestPath: (path) => path.replace(/^\/static/, ''),
    }),
  );

  app.use('*', viewMiddleware());

  /**
   * Initiates the logout process by redirecting the user to the external Identity
   * Provider's (IdP) logout endpoint. This endpoint validates that the user has an
   * active session with a valid ID token, generates a cryptographically secure state
   * parameter for CSRF protection, and stores it in a secure HTTP-only cookie.
   *
   * The state parameter will be validated upon the user's return from the IdP to
   * ensure the logout callback is legitimate and not a forged request.
   *
   * @returns A redirect response to the IdP's logout URL on success, or a 400-error
   * response if no valid session exists. The response includes a secure state cookie
   * that will be validated in the logout callback.
   */
  app.post('/auth/logout', async (c: Context): Promise<Response> => {
    const authUser: AuthUser | null = await getAuthUser(c);
    const idToken = authUser?.session.idToken;

    if (!idToken) {
      return c.json({ error: 'No valid session or ID token found' }, 400);
    }

    const { url, state } = await buildLogoutUrl(idToken);
    setCookie(c, 'logout_state', state, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/auth/logout/callback',
    });
    return c.redirect(url);
  });

  /**
   * Handles the callback from an external Identity Provider (IdP) after a user
   * signs out. This endpoint is responsible for validating the logout request to
   * prevent Cross-Site Request Forgery (CSRF) attacks by comparing a `state`
   * parameter from the URL with a value stored in a secure, server-side cookie.
   * If validation is successful, it clears the user's session cookies and
   * redirects to a success page. Otherwise, it redirects to an error page.
   *
   * @param c - The Hono context object, which contains the request and
   *            response functionality.
   * @returns A Response object that either redirects the user to a success
   * or error page. Upon success, it includes headers to delete session cookies.
   */
  app.get('/auth/logout/callback', async (c: Context): Promise<Response> => {
    const state: string | undefined = c.req.query('state');
    const logoutStateCookie: string | undefined = getCookie(c, 'logout_state');

    if (state && logoutStateCookie && state === logoutStateCookie) {
      c.header('Clear-Site-Data', '"cookies"');
      return c.redirect('/auth/logout/success');
    } else {
      const reason: string = encodeURIComponent(
        'Invalid or missing state parameter.',
      );
      return c.redirect(`/auth/logout/error?reason=${reason}`);
    }
  });

  /**
   * GET /auth/login
   *
   * Renders a custom sign-in page that displays available authentication providers
   * and handles authentication errors with user-friendly messaging. This page is
   * shown when users need to authenticate, either by visiting directly or after
   * being redirected from protected routes via the requireAuth middleware.
   *
   * The sign-in page provides a branded authentication experience that matches the
   * application's design system, rather than using Auth.js default pages. It
   * supports error display, callback URL preservation, and CSRF protection via
   * client-side JavaScript.
   *
   * Authentication flow:
   * 1. User visits protected route without session
   * 2. requireAuth redirects to /auth/login?callbackUrl=<original-url>
   * 3. This route renders custom sign-in page with available providers
   * 4. User selects provider, CSRF token is fetched and added via JavaScript
   * 5. Form submits to /auth/signin/[provider] to initiate OAuth flow
   * 6. After successful authentication, user is redirected to callbackUrl
   *
   * Error handling supports all Auth.js error types including AccessDenied,
   * Configuration, OAuthCallback, and others, displaying contextual messages
   * via the getMessage utility function.
   *
   * The page specifically looks for the 'zitadel' provider to match the original
   * implementation behavior, showing only that provider's sign-in option even
   * if multiple providers are configured.
   *
   * @param c - Hono Context object containing query parameters:
   *              - callbackUrl: URL to redirect after successful authentication
   *              - error: Auth.js error code for display (optional)
   */
  /**
   * GET /auth/signin
   *
   * Renders a custom sign-in page that displays available authentication providers
   * and handles authentication errors with user-friendly messaging. This page is
   * shown when users need to authenticate, either by visiting directly or after
   * being redirected from protected routes via the requireAuth middleware.
   *
   * The sign-in page provides a branded authentication experience that matches the
   * application's design system, rather than using Auth.js default pages. It
   * supports error display, callback URL preservation, and CSRF protection via
   * client-side JavaScript.
   *
   * Authentication flow:
   * 1. User visits protected route without session
   * 2. requireAuth redirects to /auth/login?callbackUrl=<original-url>
   * 3. This route renders custom sign-in page with available providers
   * 4. User selects provider, CSRF token is fetched and added via JavaScript
   * 5. Form submits to /auth/signin/[provider] to initiate OAuth flow
   * 6. After successful authentication, user is redirected to callbackUrl
   *
   * Error handling supports all Auth.js error types including AccessDenied,
   * Configuration, OAuthCallback, and others, displaying contextual messages
   * via the getMessage utility function.
   *
   * The page specifically looks for the 'zitadel' provider to match the original
   * implementation behavior, showing only that provider's sign-in option even
   * if multiple providers are configured.
   *
   * @param c - Hono Context object containing query parameters:
   *              - callbackUrl: URL to redirect after successful authentication
   *              - error: Auth.js error code for display (optional)
   */
  app.get('/auth/login', async (c: Context) => {
    const callbackUrl = c.req.query('callbackUrl');
    const error = c.req.query('error');

    const providers: Provider[] = authConfig.providers.map((provider) => {
      const config = typeof provider === 'function' ? provider() : provider;
      return {
        id: config.id,
        name: config.name,
        signinUrl: `/auth/signin/${config.id}`,
      };
    });

    return c.view('auth/login', {
      providers,
      callbackUrl,
      message: error ? getMessage(error, 'signin-error') : undefined,
    });
  });

  /**
   * GET /auth/error
   *
   * Intercepts authentication-related errors (e.g. AccessDenied, Configuration,
   * Verification) from sign-in or callback flows and shows a friendly error page.
   *
   * @param c  - The Hono context. May have `c.req.query('error')` set to an
   *             error code string.
   */
  app.get('/auth/error', (c: Context) => {
    const error = c.req.query('error');
    const { heading, message } = getMessage(error, 'auth-error');
    return c.view('auth/error', { heading, message });
  });

  /**
   * ZITADEL UserInfo endpoint
   *
   * Fetches extended user information from ZITADEL's UserInfo endpoint using the
   * current session's access token. Provides real-time user data including roles,
   * custom attributes, and organization membership that may not be in the cached session.
   *
   * @param c - Hono Context object
   */
  app.get(
    '/auth/userinfo',
    requireAuth,
    async (c: Context): Promise<Response> => {
      const authUser = await getAuthUser(c);
      if (!authUser) {
        return c.json({ error: 'Unauthorized' }, 401);
      }
      const token = authUser.session.accessToken;
      if (!token) {
        return c.json({ error: 'No access token available' }, 401);
      }
      try {
        const idpRes = await fetch(
          `${config.ZITADEL_DOMAIN}/oidc/v1/userinfo`,
          { headers: { Authorization: `Bearer ${token}` } },
        );
        if (!idpRes.ok) {
          return new Response(
            JSON.stringify({ error: `UserInfo API error: ${idpRes.status}` }),
            {
              status: idpRes.status,
              headers: { 'Content-Type': 'application/json' },
            },
          );
        }
        const userInfo = await idpRes.json();
        return c.json(userInfo);
      } catch (err) {
        console.error('UserInfo fetch failed:', err);
        return c.json({ error: 'Failed to fetch user info' }, 500);
      }
    },
  );

  /**
   * Home page.
   *
   * Retrieves the current Auth.js session (if any) to determine whether the
   * user is signed in, then renders the 'index' template. The template is
   * provided with:
   * - `isAuthenticated`: a boolean flag indicating session presence
   * - `loginUrl`: the URL to begin the sign-in flow
   *
   * @param c  Hono Context object for the incoming HTTP request
   */
  app.get('/', async (c: Context) => {
    const session = await getAuthUser(c);
    return c.view('index', {
      isAuthenticated: Boolean(session),
      loginUrl: '/auth/signin/zitadel',
    });
  });

  /**
   * GET /auth/logout/success
   *
   * Renders a confirmation page indicating the user has successfully logged out.
   * After displaying a success message, the template may include client-side logic
   * to redirect the user back to the home page after a short delay.
   *
   * @param c  - Hono Context object (unused)
   */
  app.get('/auth/logout/success', (c: Context) => {
    return c.view('auth/logout/success');
  });

  /**
   * GET /auth/logout/error
   *
   * Displays a user-friendly error page for failed logout attempts. This page is
   * typically shown when a security check fails during the logout process,
   * commonly due to a CSRF protection failure where the `state` parameter from
   * the identity provider does not match the one stored securely in session.
   *
   * @param c   - Hono Context object containing the query parameter `reason`
   */
  app.get('/auth/logout/error', (c: Context) => {
    const reason = c.req.query('reason') ?? 'An unknown error occurred.';
    return c.view('auth/logout/error', { reason });
  });

  /**
   * Mounts Auth.js Hono middleware to handle OAuth 2.0/OIDC authentication flows.
   *
   * This middleware provides the complete authentication infrastructure including
   * sign-in, sign-out, callback handling, session management, and CSRF protection.
   * It automatically creates endpoints for OAuth flows under the `/auth` path.
   *
   * The authHandler middleware registers several endpoints for authentication:
   * - `/auth/signin/[provider]` - Initiates OAuth flow with specified provider
   * - `/auth/callback/[provider]` - Handles OAuth callback from provider
   * - `/auth/signout` - Signs out user and clears session
   * - `/auth/session` - Returns current session data as JSON
   * - `/auth/csrf` - Returns CSRF token for form submissions
   *
   * IMPORTANT: All custom `/auth/*` routes MUST be defined BEFORE this
   * middleware to prevent conflicts. Hono matches routes in definition order,
   * and this middleware will intercept ALL `/auth/*` requests that don't match
   * your custom routes first.
   *
   * Correct Order:
   * ```typescript
   * // ✓ Define custom auth routes FIRST
   * app.get('/auth/logout/success', handler);
   * app.get('/auth/logout/error', handler);
   * app.get('/auth/error', handler);
   *
   * // ✓ Mount authHandler AFTER custom routes
   * app.use('/auth/*', authHandler());
   * ```
   *
   * Incorrect Order (will cause UnknownAction errors):
   * ```typescript
   * // ✗ authHandler intercepts everything first
   * app.use('/auth/*', authHandler());
   *
   * // ✗ These routes will never be reached
   * app.get('/auth/logout/success', handler);
   * ```
   *
   * If a request matches `/auth/*` but isn't a recognized Auth.js action, the
   * middleware throws an UnknownAction error. This happens when:
   * - Custom auth routes are defined after this middleware
   * - Invalid or misspelled auth endpoints are accessed
   * - Routes conflict with Auth.js internal naming conventions
   *
   * The middleware behavior is controlled by the `authConfig` object which
   * includes providers, session settings, callbacks, and security options.
   * See `authConfig` in `auth/index.ts` for complete configuration details.
   *
   * @see {@link https://authjs.dev/reference/hono} Auth.js Hono documentation
   * @see {@link authConfig} Complete authentication configuration
   */
  app.use('/auth/*', authHandler());

  /**
   * GET /profile
   *
   * Profile page with detailed user information.
   *
   * Renders a comprehensive view of the signed-in user's profile — for example,
   * display name, email, roles, and any custom attributes — as well as session
   * metadata (tokens, expiry, etc.). This route is guarded by `requireAuth`, so
   * unauthenticated requests are automatically redirected into the sign-in flow.
   * After confirming authentication, we call `getAuthUser` to retrieve the latest
   * session data, then render the `profile` template with the full `user` object.
   *
   * @param c  - Hono Context object, guaranteed to have an authenticated session
   */
  app.get('/profile', requireAuth, async (c: Context) => {
    const session = await getAuthUser(c);
    return c.view('profile', {
      userJson: JSON.stringify(session, null, 2),
    });
  });

  /**
   * Catch-all 404 handler.
   *
   * This middleware is invoked when no other route matches the incoming request.
   * It responds with a 404 status and renders the 'not-found' template, providing
   * a user-friendly page indicating that the requested resource could not be found.
   *
   * @param c  - Hono Context object for the incoming request
   * @returns    void
   */
  app.notFound((c: Context): Response => {
    return c.view('not-found', {});
  });

  return app;
}
