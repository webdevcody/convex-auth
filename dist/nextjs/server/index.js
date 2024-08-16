import { jsx as _jsx } from "react/jsx-runtime";
import "server-only";
import { NextResponse, } from "next/server";
import { ConvexAuthNextjsClientProvider, } from "../client.js";
import { getRequestCookies } from "./cookies.js";
import { proxyAuthActionToConvex } from "./proxy.js";
import { handleAuthenticationInRequest } from "./request.js";
/**
 * Wrap your app with this provider in your root `layout.tsx`.
 */
export function ConvexAuthNextjsServerProvider(props) {
    const { apiRoute, storage, storageNamespace, verbose, children } = props;
    return (_jsx(ConvexAuthNextjsClientProvider, { serverState: convexAuthNextjsServerState(), apiRoute: apiRoute, storage: storage, storageNamespace: storageNamespace, verbose: verbose, children: children }));
}
/**
 * Retrieve the token for authenticating calls to your
 * Convex backend from Server Components, Server Actions and Route Handlers.
 * @returns The token if the the client is authenticated, otherwise `undefined`.
 */
export function convexAuthNextjsToken() {
    return getRequestCookies().token ?? undefined;
}
/**
 * Whether the client is authenticated, which you can check
 * in Server Actions, Route Handlers and Middleware.
 *
 * Avoid the pitfall of checking authentication state in layouts,
 * since they won't stop nested pages from rendering.
 */
export function isAuthenticatedNextjs() {
    return convexAuthNextjsToken() !== undefined;
}
/**
 * Use in your `middleware.ts` to enable your Next.js app to use
 * Convex Auth for authentication on the server.
 *
 * @returns A Next.js middleware.
 */
export function convexAuthNextjsMiddleware(
/**
 * A custom handler, which you can use to decide
 * which routes should be accessible based on the client's authentication.
 */
handler, options = {}) {
    return async (request, event) => {
        const requestUrl = new URL(request.url);
        // Proxy signIn and signOut actions to Convex backend
        if (requestUrl.pathname === (options?.apiRoute ?? "/api/auth")) {
            return await proxyAuthActionToConvex(request, options);
        }
        // Refresh tokens, handle code query param
        const authResult = await handleAuthenticationInRequest(request);
        // If redirecting, proceed, the middleware will run again on next request
        if (authResult?.headers.get("Location")) {
            return authResult;
        }
        // Forward cookies to request for custom handler
        if (handler !== undefined && authResult.headers) {
            authResult.cookies.getAll().forEach((cookie) => {
                request.cookies.set(cookie.name, cookie.value);
            });
        }
        // Maybe call the custom handler
        const response = (await handler?.(request, event)) ?? NextResponse.next();
        // Port the cookies from the auth middleware to the response
        if (authResult.headers) {
            authResult.headers.forEach((value, key) => {
                response.headers.append(key, value);
            });
        }
        return response;
    };
}
export { createRouteMatcher } from "./routeMatcher.js";
/**
 * Helper for redirecting to a different route from
 * a Next.js middleware.
 *
 * ```ts
 * return nextjsMiddlewareRedirect(request, "/login");
 * ```
 */
export function nextjsMiddlewareRedirect(
/**
 * The incoming request handled by the middleware.
 */
request, 
/**
 * The route path to redirect to.
 */
pathname) {
    const url = request.nextUrl.clone();
    url.pathname = pathname;
    return NextResponse.redirect(url);
}
function convexAuthNextjsServerState() {
    const { token } = getRequestCookies();
    return {
        // The server doesn't share the refresh token with the client
        // for added security - the client has to use the server
        // to refresh the access token via cookies.
        _state: { token, refreshToken: "dummy" },
        _timeFetched: Date.now(),
    };
}
