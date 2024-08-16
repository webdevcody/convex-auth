import { Cookie } from "@auth/core/lib/utils/cookie";
import { OAuth2Config, OAuthConfig, OAuthEndpointType, OIDCConfig, TokenEndpointHandler, UserinfoEndpointHandler } from "@auth/core/providers";
import { Account, TokenSet } from "@auth/core/types";
export type InternalProvider = (OAuthConfigInternal<any> | OIDCConfigInternal<any>) & {
    signinUrl: string;
};
export declare function getAuthorizationURL(provider: InternalProvider): Promise<{
    redirect: string;
    cookies: Cookie[];
    signature: string;
}>;
export declare function handleOAuthCallback(provider: InternalProvider, request: Request, cookies: Record<string, string | undefined>): Promise<{
    profile: unknown;
    cookies: Cookie[];
    tokens: TokenSet & Pick<Account, "expires_at">;
    signature: string;
}>;
type OIDCConfigInternal<Profile> = OAuthConfigInternal<Profile> & {
    checks: OIDCConfig<Profile>["checks"];
};
type OAuthConfigInternal<Profile> = Omit<OAuthConfig<Profile>, OAuthEndpointType | "redirectProxyUrl"> & {
    authorization?: {
        url: URL;
    };
    token?: {
        url: URL;
        request?: TokenEndpointHandler["request"];
    };
    userinfo?: {
        url: URL;
        request?: UserinfoEndpointHandler["request"];
    };
    /**
     * Reconstructed from {@link OAuth2Config.redirectProxyUrl},
     * adding the callback action and provider id onto the URL.
     *
     * If defined, it is favoured over {@link OAuthConfigInternal.callbackUrl} in the authorization request.
     *
     * When {@link InternalOptions.isOnRedirectProxy} is set, the actual value is saved in the decoded `state.origin` parameter.
     *
     * @example `"https://auth.example.com/api/auth/callback/:provider"`
     *
     */
    redirectProxyUrl?: OAuth2Config<Profile>["redirectProxyUrl"];
} & Pick<Required<OAuthConfig<Profile>>, "clientId" | "checks" | "profile" | "account">;
export {};
