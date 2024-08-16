import "server-only";
import { NextRequest } from "next/server";
export declare function proxyAuthActionToConvex(request: NextRequest, options: {
    convexUrl?: string;
}): Promise<Response>;
