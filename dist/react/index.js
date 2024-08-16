/**
 * React bindings for Convex Auth.
 *
 * @module
 */
"use client";
import { jsx as _jsx } from "react/jsx-runtime";
import { ConvexHttpClient } from "convex/browser";
import { ConvexProviderWithAuth } from "convex/react";
import { useContext, useMemo } from "react";
import { AuthProvider, ConvexAuthActionsContext, ConvexAuthTokenContext, useAuth, } from "./client.js";
/**
 * Use this hook to access the `signIn` and `signOut` methods:
 *
 * ```ts
 * import { useAuthActions } from "@convex-dev/auth/react";
 *
 * function SomeComponent() {
 *   const { signIn, signOut } = useAuthActions();
 *   // ...
 * }
 * ```
 */
export function useAuthActions() {
    return useContext(ConvexAuthActionsContext);
}
/**
 * Replace your `ConvexProvider` with this component to enable authentication.
 *
 * ```tsx
 * import { ConvexAuthProvider } from "@convex-dev/auth/react";
 * import { ConvexReactClient } from "convex/react";
 * import { ReactNode } from "react";
 *
 * const convex = new ConvexReactClient(/* ... *\/);
 *
 * function RootComponent({ children }: { children: ReactNode }) {
 *   return <ConvexAuthProvider client={convex}>{children}</ConvexAuthProvider>;
 * }
 * ```
 */
export function ConvexAuthProvider(props) {
    const { client, storage, storageNamespace, replaceURL, children } = props;
    const authClient = useMemo(() => ({
        authenticatedCall(action, args) {
            return client.action(action, args);
        },
        unauthenticatedCall(action, args) {
            return new ConvexHttpClient(client.address).action(action, args);
        },
        verbose: client.options?.verbose,
    }), [client]);
    return (_jsx(AuthProvider, { client: authClient, storage: storage ??
            // Handle SSR, RN, Web, etc.
            // Pretend we always have storage, the component checks
            // it in first useEffect.
            (typeof window === "undefined" ? undefined : window?.localStorage), storageNamespace: storageNamespace ?? client.address, replaceURL: replaceURL ??
            ((url) => {
                window.history.replaceState({}, "", url);
            }), children: _jsx(ConvexProviderWithAuth, { client: client, useAuth: useAuth, children: children }) }));
}
/**
 * Use this hook to access the JWT token on the client, for authenticating
 * your Convex HTTP actions.
 *
 * You should not pass this token to other servers (think of it
 * as an "ID token").
 *
 * ```ts
 * import { useAuthToken } from "@convex-dev/auth/react";
 *
 * function SomeComponent() {
 *   const token = useAuthToken();
 *   const onClick = async () => {
 *     await fetch(`${CONVEX_SITE_URL}/someEndpoint`, {
 *       headers: {
 *         Authorization: `Bearer ${token}`,
 *       },
 *     });
 *   };
 *   // ...
 * }
 * ```
 */
export function useAuthToken() {
    return useContext(ConvexAuthTokenContext);
}
