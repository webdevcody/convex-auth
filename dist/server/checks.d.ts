import { InternalProvider } from "./oauth.js";
export declare const state: {
    create(provider: InternalProvider): {
        state: string;
        cookie: {
            name: string;
            value: string;
            options: {
                maxAge: number;
                httpOnly: boolean;
                sameSite: "none";
                secure: boolean;
                path: string;
                partitioned: boolean;
            };
        };
    };
    use(provider: InternalProvider, cookies: Record<string, string | undefined>): {
        state: string;
        updatedCookie: {
            name: string;
            value: string;
            options: {
                maxAge: number;
                httpOnly: boolean;
                sameSite: "none";
                secure: boolean;
                path: string;
                partitioned: boolean;
            };
        };
    };
};
export declare const pkce: {
    create(provider: InternalProvider): Promise<{
        codeChallenge: string;
        codeVerifier: string;
        cookie: {
            name: string;
            value: string;
            options: {
                maxAge: number;
                httpOnly: boolean;
                sameSite: "none";
                secure: boolean;
                path: string;
                partitioned: boolean;
            };
        };
    }>;
    /**
     * An error is thrown if the code_verifier is missing or invalid.
     * @see https://www.rfc-editor.org/rfc/rfc7636
     * @see https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/#pkce
     */
    use(provider: InternalProvider, cookies: Record<string, string | undefined>): {
        codeVerifier: string;
        updatedCookie: {
            name: string;
            value: string;
            options: {
                maxAge: number;
                httpOnly: boolean;
                sameSite: "none";
                secure: boolean;
                path: string;
                partitioned: boolean;
            };
        };
    };
};
export declare const nonce: {
    create(provider: InternalProvider): Promise<{
        nonce: string;
        cookie: {
            name: string;
            value: string;
            options: {
                maxAge: number;
                httpOnly: boolean;
                sameSite: "none";
                secure: boolean;
                path: string;
                partitioned: boolean;
            };
        };
    }>;
    /**
     * An error is thrown if the nonce is missing or invalid.
     * @see https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
     * @see https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/#nonce
     */
    use(provider: InternalProvider, cookies: Record<string, string | undefined>): {
        nonce: string;
        updatedCookie: {
            name: string;
            value: string;
            options: {
                maxAge: number;
                httpOnly: boolean;
                sameSite: "none";
                secure: boolean;
                path: string;
                partitioned: boolean;
            };
        };
    };
};
export declare function redirectToParamCookie(providerId: string, redirectTo: string): {
    name: string;
    value: string;
    options: {
        maxAge: number;
        httpOnly: boolean;
        sameSite: "none";
        secure: boolean;
        path: string;
        partitioned: boolean;
    };
};
export declare function useRedirectToParam(providerId: string, cookies: Record<string, string | undefined>): {
    redirectTo: string;
    updatedCookie: {
        name: string;
        value: string;
        options: {
            maxAge: number;
            httpOnly: boolean;
            sameSite: "none";
            secure: boolean;
            path: string;
            partitioned: boolean;
        };
    };
} | null;
