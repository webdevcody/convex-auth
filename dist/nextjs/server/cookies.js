import { cookies, headers } from "next/headers";
export function getRequestCookies() {
    return getCookieStore(headers(), cookies());
}
export function getRequestCookiesInMiddleware(request) {
    return getCookieStore(headers(), request.cookies);
}
export function getResponseCookies(response) {
    return getCookieStore(headers(), response.cookies);
}
function getCookieStore(requestHeaders, responseCookies) {
    const isLocalhost = /localhost:\d+/.test(requestHeaders.get("Host") ?? "");
    const prefix = isLocalhost ? "" : "__Host-";
    const tokenName = prefix + "__convexAuthJWT";
    const refreshTokenName = prefix + "__convexAuthRefreshToken";
    const verifierName = prefix + "__convexAuthOAuthVerifier";
    function getValue(name) {
        return responseCookies.get(name)?.value ?? null;
    }
    function setValue(name, value) {
        if (value === null) {
            // Only request cookies have a `size` property
            if ("size" in responseCookies) {
                responseCookies.delete(name);
            }
            else {
                // See https://github.com/vercel/next.js/issues/56632
                // for why .delete({}) doesn't work:
                responseCookies.set(name, "", {
                    ...COOKIE_OPTIONS,
                    expires: 0,
                });
            }
        }
        else {
            responseCookies.set(name, value, COOKIE_OPTIONS);
        }
    }
    return {
        get token() {
            return getValue(tokenName);
        },
        set token(value) {
            setValue(tokenName, value);
        },
        get refreshToken() {
            return getValue(refreshTokenName);
        },
        set refreshToken(value) {
            setValue(refreshTokenName, value);
        },
        get verifier() {
            return getValue(verifierName);
        },
        set verifier(value) {
            setValue(verifierName, value);
        },
    };
}
const COOKIE_OPTIONS = {
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    path: "/",
};
