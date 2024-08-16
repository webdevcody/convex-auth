import { NextRequest, NextResponse } from "next/server";
export declare function jsonResponse(body: any): NextResponse<unknown>;
export declare function setAuthCookies(response: NextResponse, tokens: {
    token: string;
    refreshToken: string;
} | null): void;
export declare function isCorsRequest(request: NextRequest): boolean;
