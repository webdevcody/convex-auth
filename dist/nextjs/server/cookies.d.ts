import { NextRequest, NextResponse } from "next/server";
export declare function getRequestCookies(): {
    readonly token: string | null;
    readonly refreshToken: string | null;
    readonly verifier: string | null;
};
export declare function getRequestCookiesInMiddleware(request: NextRequest): {
    token: string | null;
    refreshToken: string | null;
    verifier: string | null;
};
export declare function getResponseCookies(response: NextResponse): {
    token: string | null;
    refreshToken: string | null;
    verifier: string | null;
};
