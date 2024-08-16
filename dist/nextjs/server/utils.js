import { NextResponse } from "next/server";
import { getResponseCookies } from "./cookies.js";
export function jsonResponse(body) {
    return new NextResponse(JSON.stringify(body), {
        headers: { "Content-Type": "application/json" },
    });
}
export function setAuthCookies(response, tokens) {
    const responseCookies = getResponseCookies(response);
    if (tokens === null) {
        responseCookies.token = null;
        responseCookies.refreshToken = null;
    }
    else {
        responseCookies.token = tokens.token;
        responseCookies.refreshToken = tokens.refreshToken;
    }
    responseCookies.verifier = null;
}
export function isCorsRequest(request) {
    const origin = request.headers.get("Origin");
    const originURL = origin ? new URL(origin) : null;
    return (originURL !== null &&
        (originURL.host !== request.headers.get("Host") ||
            originURL.protocol !== new URL(request.url).protocol));
}
