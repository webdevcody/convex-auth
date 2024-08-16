import "server-only";
import { NextMiddlewareResult } from "next/dist/server/web/types";
import { NextFetchEvent, NextMiddleware, NextRequest, NextResponse } from "next/server";
import { ReactNode } from "react";
/**
 * Wrap your app with this provider in your root `layout.tsx`.
 */
export declare function ConvexAuthNextjsServerProvider(props: {
    /**
     * You can customize the route path that handles authentication
     * actions via this prop and the `apiRoute` option to `convexAuthNextjsMiddleWare`.
     *
     * Defaults to `/api/auth`.
     */
    apiRoute?: string;
    /**
     * Choose how the auth information will be stored on the client.
     *
     * Defaults to `"localStorage"`.
     *
     * If you choose `"inMemory"`, different browser tabs will not
     * have a synchronized authentication state.
     */
    storage?: "localStorage" | "inMemory";
    /**
     * Optional namespace for keys used to store tokens. The keys
     * determine whether the tokens are shared or not.
     *
     * Any non-alphanumeric characters will be ignored.
     *
     * Defaults to `process.env.NEXT_PUBLIC_CONVEX_URL`.
     */
    storageNamespace?: string;
    /**
     * Turn on debugging logs.
     */
    verbose?: boolean;
    /**
     * Children components can call Convex hooks
     * and [useAuthActions](https://labs.convex.dev/auth/api_reference/react#useauthactions).
     */
    children: ReactNode;
}): import("react/jsx-runtime").JSX.Element;
/**
 * Retrieve the token for authenticating calls to your
 * Convex backend from Server Components, Server Actions and Route Handlers.
 * @returns The token if the the client is authenticated, otherwise `undefined`.
 */
export declare function convexAuthNextjsToken(): string | undefined;
/**
 * Whether the client is authenticated, which you can check
 * in Server Actions, Route Handlers and Middleware.
 *
 * Avoid the pitfall of checking authentication state in layouts,
 * since they won't stop nested pages from rendering.
 */
export declare function isAuthenticatedNextjs(): boolean;
/**
 * Use in your `middleware.ts` to enable your Next.js app to use
 * Convex Auth for authentication on the server.
 *
 * @returns A Next.js middleware.
 */
export declare function convexAuthNextjsMiddleware(
/**
 * A custom handler, which you can use to decide
 * which routes should be accessible based on the client's authentication.
 */
handler?: (request: NextRequest, event: NextFetchEvent) => NextMiddlewareResult | Promise<NextMiddlewareResult>, options?: {
    /**
     * The URL of the Convex deployment to use for authentication.
     *
     * Defaults to `process.env.NEXT_PUBLIC_CONVEX_URL`.
     */
    convexUrl?: string;
    /**
     * You can customize the route path that handles authentication
     * actions via this option and the `apiRoute` prop of `ConvexAuthNextjsProvider`.
     *
     * Defaults to `/api/auth`.
     */
    apiRoute?: string;
}): NextMiddleware;
export { createRouteMatcher, RouteMatcherParam } from "./routeMatcher.js";
/**
 * Helper for redirecting to a different route from
 * a Next.js middleware.
 *
 * ```ts
 * return nextjsMiddlewareRedirect(request, "/login");
 * ```
 */
export declare function nextjsMiddlewareRedirect(
/**
 * The incoming request handled by the middleware.
 */
request: NextRequest, 
/**
 * The route path to redirect to.
 */
pathname: string): NextResponse<unknown>;
