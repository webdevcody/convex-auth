import "server-only";
import { fetchAction } from "convex/nextjs";
import { getRequestCookies, getResponseCookies } from "./cookies.js";
import { isCorsRequest, jsonResponse, setAuthCookies } from "./utils.js";
export async function proxyAuthActionToConvex(request, options) {
    if (request.method !== "POST") {
        return new Response("Invalid method", { status: 405 });
    }
    if (isCorsRequest(request)) {
        return new Response("Invalid origin", { status: 403 });
    }
    const { action, args } = await request.json();
    if (action !== "auth:signIn" && action !== "auth:signOut") {
        return new Response("Invalid action", { status: 400 });
    }
    // The client has a dummy refreshToken, the real one is only
    // stored in cookies.
    if (action === "auth:signIn" && args.refreshToken !== undefined) {
        args.refreshToken = getRequestCookies().refreshToken;
    }
    console.log("making a request", action, args, options?.convexUrl);
    const untypedResult = await fetchAction(action, args, {
        url: options?.convexUrl,
    });
    console.log('proxy done');
    if (action === "auth:signIn") {
        const result = untypedResult;
        if (result.redirect !== undefined) {
            const { redirect } = result;
            const response = jsonResponse({ redirect });
            getResponseCookies(response).verifier = result.verifier;
            return response;
        }
        else if (result.tokens !== undefined) {
            const response = jsonResponse(result);
            console.log('setting auth cookies');
            setAuthCookies(response, result.tokens);
            return response;
        }
        return jsonResponse(result);
    }
    else {
        const response = jsonResponse(null);
        setAuthCookies(response, null);
        return response;
    }
}
