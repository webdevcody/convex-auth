import { actionGeneric, defineSchema, defineTable, httpActionGeneric, internalMutationGeneric, } from "convex/server";
import { ConvexError, v } from "convex/values";
import { parse as parseCookies, serialize as serializeCookie } from "cookie";
import { SignJWT, importPKCS8 } from "jose";
import { alphabet, generateRandomString, sha256 as rawSha256, } from "oslo/crypto";
import { encodeHex } from "oslo/encoding";
import { redirectToParamCookie, useRedirectToParam } from "./checks.js";
import { getAuthorizationURL, handleOAuthCallback } from "./oauth.js";
import { configDefaults, listAvailableProviders, materializeProvider, } from "./provider_utils.js";
import { requireEnv } from "./utils.js";
const DEFAULT_EMAIL_VERIFICATION_CODE_DURATION_S = 60 * 60 * 24; // 24 hours
const DEFAULT_SESSION_TOTAL_DURATION_MS = 1000 * 60 * 60 * 24 * 30; // 30 days
const DEFAULT_SESSION_INACTIVE_DURATION_MS = 1000 * 60 * 60 * 24 * 30; // 30 days
const DEFAULT_JWT_DURATION_MS = 1000 * 60 * 60; // 1 hour
const OAUTH_SIGN_IN_EXPIRATION_MS = 1000 * 60 * 2; // 2 minutes
const DEFAULT_MAX_SIGN_IN_ATTEMPS_PER_HOUR = 10;
const REFRESH_TOKEN_DIVIDER = "|";
const TOKEN_SUB_CLAIM_DIVIDER = "|";
/**
 * The table definitions required by the library.
 *
 * Your schema must include these so that the indexes
 * are set up:
 *
 *
 * ```ts filename="convex/schema.ts"
 * import { defineSchema } from "convex/server";
 * import { authTables } from "@convex-dev/auth/server";
 *
 * const schema = defineSchema({
 *   ...authTables,
 * });
 *
 * export default schema;
 * ```
 *
 * You can inline the table definitions into your schema
 * and extend them with additional optional and required
 * fields. See https://labs.convex.dev/auth/setup/schema
 * for more details.
 */
export const authTables = {
    /**
     * Users.
     */
    users: defineTable({
        name: v.optional(v.string()),
        image: v.optional(v.string()),
        email: v.optional(v.string()),
        emailVerificationTime: v.optional(v.number()),
        phone: v.optional(v.string()),
        phoneVerificationTime: v.optional(v.number()),
        isAnonymous: v.optional(v.boolean()),
    })
        .index("email", ["email"])
        .index("phone", ["phone"]),
    /**
     * Sessions.
     * A single user can have multiple active sessions.
     * See [Session document lifecycle](https://labs.convex.dev/auth/advanced#session-document-lifecycle).
     */
    authSessions: defineTable({
        userId: v.id("users"),
        expirationTime: v.number(),
    }).index("userId", ["userId"]),
    /**
     * Accounts. An account corresponds to
     * a single authentication provider.
     * A single user can have multiple accounts linked.
     */
    authAccounts: defineTable({
        userId: v.id("users"),
        provider: v.string(),
        providerAccountId: v.string(),
        secret: v.optional(v.string()),
        emailVerified: v.optional(v.string()),
        phoneVerified: v.optional(v.string()),
    })
        .index("userIdAndProvider", ["userId", "provider"])
        .index("accountIdAndProvider", ["providerAccountId", "provider"]),
    /**
     * Refresh tokens.
     * Each session has only a single refresh token
     * valid at a time. Refresh tokens are rotated
     * and reuse is not allowed.
     */
    authRefreshTokens: defineTable({
        sessionId: v.id("authSessions"),
        expirationTime: v.number(),
    }).index("sessionId", ["sessionId"]),
    /**
     * Verification codes:
     * - OTP tokens
     * - magic link tokens
     * - OAuth codes
     */
    authVerificationCodes: defineTable({
        accountId: v.id("authAccounts"),
        provider: v.string(),
        code: v.string(),
        expirationTime: v.number(),
        verifier: v.optional(v.string()),
        emailVerified: v.optional(v.string()),
        phoneVerified: v.optional(v.string()),
    })
        .index("accountId", ["accountId"])
        .index("code", ["code"]),
    /**
     * PKCE verifiers for OAuth.
     */
    authVerifiers: defineTable({
        sessionId: v.optional(v.id("authSessions")),
        signature: v.optional(v.string()),
    }).index("signature", ["signature"]),
    /**
     * Rate limits for OTP and password sign-in.
     */
    authRateLimits: defineTable({
        identifier: v.string(),
        lastAttemptTime: v.number(),
        attemptsLeft: v.number(),
    }).index("identifier", ["identifier"]),
};
const defaultSchema = defineSchema(authTables);
const storeArgs = {
    args: v.union(v.object({
        type: v.literal("signIn"),
        userId: v.id("users"),
        sessionId: v.optional(v.id("authSessions")),
        generateTokens: v.boolean(),
    }), v.object({
        type: v.literal("signOut"),
    }), v.object({
        type: v.literal("refreshSession"),
        refreshToken: v.string(),
    }), v.object({
        type: v.literal("verifyCodeAndSignIn"),
        params: v.any(),
        provider: v.optional(v.string()),
        verifier: v.optional(v.string()),
        generateTokens: v.boolean(),
        allowExtraProviders: v.boolean(),
    }), v.object({
        type: v.literal("verifier"),
    }), v.object({
        type: v.literal("verifierSignature"),
        verifier: v.string(),
        signature: v.string(),
    }), v.object({
        type: v.literal("userOAuth"),
        provider: v.string(),
        providerAccountId: v.string(),
        profile: v.any(),
        signature: v.string(),
    }), v.object({
        type: v.literal("createVerificationCode"),
        accountId: v.optional(v.id("authAccounts")),
        provider: v.string(),
        email: v.optional(v.string()),
        phone: v.optional(v.string()),
        code: v.string(),
        expirationTime: v.number(),
        allowExtraProviders: v.boolean(),
    }), v.object({
        type: v.literal("createAccountFromCredentials"),
        provider: v.string(),
        account: v.object({ id: v.string(), secret: v.optional(v.string()) }),
        profile: v.any(),
        shouldLinkViaEmail: v.optional(v.boolean()),
        shouldLinkViaPhone: v.optional(v.boolean()),
    }), v.object({
        type: v.literal("retrieveAccountWithCredentials"),
        provider: v.string(),
        account: v.object({ id: v.string(), secret: v.optional(v.string()) }),
    }), v.object({
        type: v.literal("modifyAccount"),
        provider: v.string(),
        account: v.object({ id: v.string(), secret: v.string() }),
    }), v.object({
        type: v.literal("invalidateSessions"),
        userId: v.id("users"),
        except: v.optional(v.array(v.id("authSessions"))),
    })),
};
const internal = {
    auth: {
        store: "auth:store",
    },
};
/**
 * Configure the Convex Auth library. Returns an object with
 * functions and `auth` helper. You must export the functions
 * from `convex/auth.ts` to make them callable:
 *
 * ```ts filename="convex/auth.ts"
 * import { convexAuth } from "@convex-dev/auth/server";
 *
 * export const { auth, signIn, signOut, store } = convexAuth({
 *   providers: [],
 * });
 * ```
 *
 * @returns An object with `auth` helper for configuring HTTP actions and accessing
 * the current user and session ID.
 */
export function convexAuth(config_) {
    const config = configDefaults(config_);
    const hasOAuth = config.providers.some((provider) => provider.type === "oauth" || provider.type === "oidc");
    const getProvider = (id, allowExtraProviders = false) => {
        return (config.providers.find((provider) => provider.id === id) ??
            (allowExtraProviders
                ? config.extraProviders.find((provider) => provider.id === id)
                : undefined));
    };
    const getProviderOrThrow = (id, allowExtraProviders = false) => {
        const provider = getProvider(id, allowExtraProviders);
        if (provider === undefined) {
            const message = `Provider \`${id}\` is not configured, ` +
                `available providers are ${listAvailableProviders(config, allowExtraProviders)}.`;
            console.error(message);
            throw new Error(message);
        }
        return provider;
    };
    const enrichCtx = (ctx) => ({ ...ctx, auth: { ...ctx.auth, config } });
    const auth = {
        /**
         * Return the currently signed-in user's ID.
         *
         * ```ts filename="convex/myFunctions.tsx"
         * import { mutation } from "./_generated/server";
         * import { auth } from "./auth.js";
         *
         * export const doSomething = mutation({
         *   args: {/* ... *\/},
         *   handler: async (ctx, args) => {
         *     const userId = await auth.getUserId(ctx);
         *     if (userId === null) {
         *       throw new Error("Client is not authenticated!")
         *     }
         *     const user = await ctx.db.get(userId);
         *     // ...
         *   },
         * });
         * ```
         *
         * @param ctx query, mutation or action `ctx`
         * @returns the user ID or `null` if the client isn't authenticated
         */
        getUserId: async (ctx) => {
            const identity = await ctx.auth.getUserIdentity();
            if (identity === null) {
                return null;
            }
            const [userId] = identity.subject.split(TOKEN_SUB_CLAIM_DIVIDER);
            return userId;
        },
        /**
         * Return the current session ID.
         *
         * ```ts filename="convex/myFunctions.tsx"
         * import { mutation } from "./_generated/server";
         * import { auth } from "./auth.js";
         *
         * export const doSomething = mutation({
         *   args: {/* ... *\/},
         *   handler: async (ctx, args) => {
         *     const sessionId = await auth.getSessionId(ctx);
         *     if (sessionId === null) {
         *       throw new Error("Client is not authenticated!")
         *     }
         *     const session = await ctx.db.get(sessionId);
         *     // ...
         *   },
         * });
         * ```
         *
         * @param ctx query, mutation or action `ctx`
         * @returns the session ID or `null` if the client isn't authenticated
         */
        getSessionId: async (ctx) => {
            const identity = await ctx.auth.getUserIdentity();
            if (identity === null) {
                return null;
            }
            const [, sessionId] = identity.subject.split(TOKEN_SUB_CLAIM_DIVIDER);
            return sessionId;
        },
        /**
         * Add HTTP actions for JWT verification and OAuth sign-in.
         *
         * ```ts
         * import { httpRouter } from "convex/server";
         * import { auth } from "./auth.js";
         *
         * const http = httpRouter();
         *
         * auth.addHttpRoutes(http);
         *
         * export default http;
         * ```
         *
         * The following routes are handled always:
         *
         * - `/.well-known/openid-configuration`
         * - `/.well-known/jwks.json`
         *
         * The following routes are handled if OAuth is configured:
         *
         * - `/api/auth/signin/*`
         * - `/api/auth/callback/*`
         *
         * @param http your HTTP router
         */
        addHttpRoutes: (http) => {
            http.route({
                path: "/.well-known/openid-configuration",
                method: "GET",
                handler: httpActionGeneric(async () => {
                    return new Response(JSON.stringify({
                        issuer: requireEnv("CONVEX_SITE_URL"),
                        jwks_uri: requireEnv("CONVEX_SITE_URL") + "/.well-known/jwks.json",
                        authorization_endpoint: requireEnv("CONVEX_SITE_URL") + "/oauth/authorize",
                    }), {
                        status: 200,
                        headers: {
                            "Content-Type": "application/json",
                            "Cache-Control": "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400",
                        },
                    });
                }),
            });
            http.route({
                path: "/.well-known/jwks.json",
                method: "GET",
                handler: httpActionGeneric(async () => {
                    return new Response(requireEnv("JWKS"), {
                        status: 200,
                        headers: {
                            "Content-Type": "application/json",
                            "Cache-Control": "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400",
                        },
                    });
                }),
            });
            if (hasOAuth) {
                http.route({
                    pathPrefix: "/api/auth/signin/",
                    method: "GET",
                    handler: httpActionGeneric(convertErrorsToResponse(400, async (ctx, request) => {
                        const url = new URL(request.url);
                        const pathParts = url.pathname.split("/");
                        const providerId = pathParts.at(-1);
                        if (providerId === null) {
                            throw new Error("Missing provider id");
                        }
                        const verifier = url.searchParams.get("code");
                        if (verifier === null) {
                            throw new Error("Missing sign-in verifier");
                        }
                        const provider = getProviderOrThrow(providerId);
                        const { redirect, cookies, signature } = await getAuthorizationURL(provider);
                        await ctx.runMutation(internal.auth.store, {
                            args: {
                                type: "verifierSignature",
                                verifier,
                                signature,
                            },
                        });
                        const redirectTo = url.searchParams.get("redirectTo");
                        if (redirectTo !== null) {
                            cookies.push(redirectToParamCookie(providerId, redirectTo));
                        }
                        const headers = new Headers({ Location: redirect });
                        for (const { name, value, options } of cookies) {
                            headers.append("Set-Cookie", serializeCookie(name, value, options));
                        }
                        return new Response(null, { status: 302, headers });
                    })),
                });
                const callbackAction = httpActionGeneric(async (ctx, request) => {
                    const url = new URL(request.url);
                    const pathParts = url.pathname.split("/");
                    const providerId = pathParts.at(-1);
                    const provider = getProviderOrThrow(providerId);
                    const cookies = getCookies(request);
                    const maybeRedirectTo = useRedirectToParam(provider.id, cookies);
                    const destinationUrl = await redirectAbsoluteUrl(config, {
                        redirectTo: maybeRedirectTo?.redirectTo,
                    });
                    try {
                        const { profile, tokens, signature } = await handleOAuthCallback(provider, request, cookies);
                        const { id, ...profileFromCallback } = await provider.profile(profile, tokens);
                        if (typeof id !== "string") {
                            throw new Error(`The profile method of the ${providerId} config must return a string ID`);
                        }
                        const verificationCode = await ctx.runMutation(internal.auth.store, {
                            args: {
                                type: "userOAuth",
                                provider: providerId,
                                providerAccountId: id,
                                profile: profileFromCallback,
                                signature,
                            },
                        });
                        return new Response(null, {
                            status: 302,
                            headers: {
                                Location: setURLSearchParam(destinationUrl, "code", verificationCode),
                                "Cache-Control": "must-revalidate",
                            },
                        });
                    }
                    catch (error) {
                        logError(error);
                        return Response.redirect(destinationUrl);
                    }
                });
                http.route({
                    pathPrefix: "/api/auth/callback/",
                    method: "GET",
                    handler: callbackAction,
                });
                http.route({
                    pathPrefix: "/api/auth/callback/",
                    method: "POST",
                    handler: callbackAction,
                });
            }
        },
    };
    return {
        /**
         * Helper for configuring HTTP actions and accessing
         * the current user and session ID.
         */
        auth,
        /**
         * Action called by the client to sign the user in.
         *
         * Also used for refreshing the session.
         */
        signIn: actionGeneric({
            args: {
                provider: v.optional(v.string()),
                params: v.optional(v.any()),
                verifier: v.optional(v.string()),
                refreshToken: v.optional(v.string()),
            },
            handler: async (ctx, args) => {
                const provider = args.provider !== undefined
                    ? getProviderOrThrow(args.provider)
                    : null;
                const result = await signInImpl(enrichCtx(ctx), provider, args, {
                    generateTokens: true,
                    allowExtraProviders: false,
                });
                return result.redirect !== undefined
                    ? { redirect: result.redirect, verifier: result.verifier }
                    : result.started !== undefined
                        ? { started: result.started }
                        : { tokens: result.signedIn?.tokens ?? null };
            },
        }),
        /**
         * Action called by the client to invalidate the current session.
         */
        signOut: actionGeneric({
            args: {},
            handler: async (ctx) => {
                await ctx.runMutation(internal.auth.store, {
                    args: { type: "signOut" },
                });
            },
        }),
        /**
         * Internal mutation used by the library to read and write
         * to the database during signin and signout.
         */
        store: internalMutationGeneric({
            args: storeArgs,
            handler: async (ctx, { args }) => {
                // console.debug(args);
                switch (args.type) {
                    case "signIn": {
                        const { userId, sessionId: existingSessionId, generateTokens, } = args;
                        const sessionId = existingSessionId ??
                            (await createNewAndDeleteExistingSession(ctx, config, auth, userId));
                        return await maybeGenerateTokensForSession(ctx, config, userId, sessionId, generateTokens);
                    }
                    case "signOut": {
                        const sessionId = await auth.getSessionId(ctx);
                        if (sessionId !== null) {
                            const session = await ctx.db.get(sessionId);
                            if (session !== null) {
                                await deleteSession(ctx, session);
                                return { userId: session.userId, sessionId: session._id };
                            }
                        }
                        return null;
                    }
                    case "refreshSession": {
                        const { refreshToken } = args;
                        const [refreshTokenId, tokenSessionId] = refreshToken.split(REFRESH_TOKEN_DIVIDER);
                        const validationResult = await validateRefreshToken(ctx, refreshTokenId, tokenSessionId);
                        // This invalidates all other refresh tokens for this session,
                        // including ones created later, regardless of whether
                        // the passed one is valid or not.
                        await deleteRefreshTokens(ctx, tokenSessionId);
                        if (validationResult === null) {
                            // Can't call `deleteSession` here because we already deleted
                            // refresh tokens above
                            const session = await ctx.db.get(tokenSessionId);
                            if (session !== null) {
                                await ctx.db.delete(session._id);
                            }
                            return null;
                        }
                        const { session } = validationResult;
                        const sessionId = session._id;
                        const userId = session.userId;
                        return await generateTokensForSession(ctx, config, userId, sessionId);
                    }
                    case "verifyCodeAndSignIn": {
                        const { generateTokens, provider, allowExtraProviders } = args;
                        const identifier = args.params.email ?? args.params.phone;
                        if (identifier !== undefined) {
                            if (await isSignInRateLimited(ctx, identifier, config)) {
                                console.error("Too many failed attemps to verify code for this email");
                                return null;
                            }
                        }
                        const verifyResult = await verifyCodeOnly(ctx, args, provider ?? null, getProviderOrThrow, allowExtraProviders, config, await auth.getSessionId(ctx));
                        if (verifyResult === null) {
                            if (identifier !== undefined) {
                                await recordFailedSignIn(ctx, identifier, config);
                            }
                            return null;
                        }
                        if (identifier !== undefined) {
                            await resetSignInRateLimit(ctx, identifier);
                        }
                        const { userId } = verifyResult;
                        const sessionId = await createNewAndDeleteExistingSession(ctx, config, auth, userId);
                        return await maybeGenerateTokensForSession(ctx, config, userId, sessionId, generateTokens);
                    }
                    case "verifier": {
                        return await ctx.db.insert("authVerifiers", {
                            sessionId: (await auth.getSessionId(ctx)) ?? undefined,
                        });
                    }
                    case "verifierSignature": {
                        const { verifier, signature } = args;
                        const verifierDoc = await ctx.db.get(verifier);
                        if (verifierDoc === null) {
                            throw new Error("Invalid verifier");
                        }
                        return await ctx.db.patch(verifierDoc._id, { signature });
                    }
                    case "userOAuth": {
                        const { profile, provider, providerAccountId, signature } = args;
                        const providerConfig = getProviderOrThrow(provider);
                        const existingAccount = await ctx.db
                            .query("authAccounts")
                            .withIndex("accountIdAndProvider", (q) => q
                            .eq("providerAccountId", providerAccountId)
                            .eq("provider", provider))
                            .unique();
                        const verifier = await ctx.db
                            .query("authVerifiers")
                            .withIndex("signature", (q) => q.eq("signature", signature))
                            .unique();
                        if (verifier === null) {
                            throw new Error("Invalid state");
                        }
                        const { accountId } = await upsertUserAndAccount(ctx, verifier.sessionId ?? null, existingAccount !== null
                            ? { existingAccount }
                            : { providerAccountId }, { type: "oauth", provider: providerConfig, profile }, config);
                        const code = generateRandomString(8, alphabet("0-9"));
                        await ctx.db.delete(verifier._id);
                        const existingVerificationCode = await ctx.db
                            .query("authVerificationCodes")
                            .withIndex("accountId", (q) => q.eq("accountId", accountId))
                            .unique();
                        if (existingVerificationCode !== null) {
                            await ctx.db.delete(existingVerificationCode._id);
                        }
                        await ctx.db.insert("authVerificationCodes", {
                            code: await sha256(code),
                            accountId,
                            provider,
                            expirationTime: Date.now() + OAUTH_SIGN_IN_EXPIRATION_MS,
                            // The use of a verifier means we don't need an identifier
                            // during verification.
                            verifier: verifier._id,
                        });
                        return code;
                    }
                    case "createVerificationCode": {
                        const { email, phone, code, expirationTime, provider: providerId, accountId: existingAccountId, allowExtraProviders, } = args;
                        const existingAccount = existingAccountId !== undefined
                            ? await getAccountOrThrow(ctx, existingAccountId)
                            : await ctx.db
                                .query("authAccounts")
                                .withIndex("accountIdAndProvider", (q) => q
                                .eq("providerAccountId", email ?? phone)
                                .eq("provider", providerId))
                                .unique();
                        const provider = getProviderOrThrow(providerId, allowExtraProviders);
                        const { accountId } = await upsertUserAndAccount(ctx, await auth.getSessionId(ctx), existingAccount !== null
                            ? { existingAccount }
                            : { providerAccountId: email ?? phone }, provider.type === "email"
                            ? { type: "email", provider, profile: { email: email } }
                            : { type: "phone", provider, profile: { phone: phone } }, config);
                        await generateUniqueVerificationCode(ctx, accountId, providerId, code, expirationTime, { email, phone });
                        return email ?? phone;
                    }
                    case "createAccountFromCredentials": {
                        const { provider: providerId, account, profile, shouldLinkViaEmail, shouldLinkViaPhone, } = args;
                        const provider = getProviderOrThrow(providerId);
                        const existingAccount = await ctx.db
                            .query("authAccounts")
                            .withIndex("accountIdAndProvider", (q) => q
                            .eq("providerAccountId", account.id)
                            .eq("provider", provider.id))
                            .unique();
                        if (existingAccount !== null) {
                            if (account.secret !== undefined &&
                                !(await verify(provider, account.secret, existingAccount.secret ?? ""))) {
                                throw new Error(`Account ${account.id} already exists`);
                            }
                            return {
                                account: existingAccount,
                                // TODO: Ian removed this,
                                user: await ctx.db.get(existingAccount.userId),
                            };
                        }
                        const secret = account.secret !== undefined
                            ? await hash(provider, account.secret)
                            : undefined;
                        const { userId, accountId } = await upsertUserAndAccount(ctx, await auth.getSessionId(ctx), { providerAccountId: account.id, secret }, {
                            type: "credentials",
                            provider,
                            profile,
                            shouldLinkViaEmail,
                            shouldLinkViaPhone,
                        }, config);
                        return {
                            account: await ctx.db.get(accountId),
                            user: await ctx.db.get(userId),
                        };
                    }
                    case "retrieveAccountWithCredentials": {
                        const { provider: providerId, account } = args;
                        const existingAccount = await ctx.db
                            .query("authAccounts")
                            .withIndex("accountIdAndProvider", (q) => q
                            .eq("providerAccountId", account.id)
                            .eq("provider", providerId))
                            .unique();
                        if (existingAccount === null) {
                            return "InvalidAccountId";
                        }
                        if (account.secret !== undefined) {
                            if (await isSignInRateLimited(ctx, existingAccount._id, config)) {
                                return "TooManyFailedAttempts";
                            }
                            if (!(await verify(getProviderOrThrow(providerId), account.secret, existingAccount.secret ?? ""))) {
                                await recordFailedSignIn(ctx, existingAccount._id, config);
                                return "InvalidSecret";
                            }
                            await resetSignInRateLimit(ctx, existingAccount._id);
                        }
                        return {
                            account: existingAccount,
                            // TODO: Ian removed this
                            user: await ctx.db.get(existingAccount.userId),
                        };
                    }
                    case "modifyAccount": {
                        const { provider, account } = args;
                        const existingAccount = await ctx.db
                            .query("authAccounts")
                            .withIndex("accountIdAndProvider", (q) => q.eq("providerAccountId", account.id).eq("provider", provider))
                            .unique();
                        if (existingAccount === null) {
                            throw new Error(`Cannot modify account with ID ${account.id} because it does not exist`);
                        }
                        await ctx.db.patch(existingAccount._id, {
                            secret: await hash(getProviderOrThrow(provider), account.secret),
                        });
                        return;
                    }
                    case "invalidateSessions": {
                        const { userId, except } = args;
                        const exceptSet = new Set(except ?? []);
                        const sessions = await ctx.db
                            .query("authSessions")
                            .withIndex("userId", (q) => q.eq("userId", userId))
                            .collect();
                        for (const session of sessions) {
                            if (!exceptSet.has(session._id)) {
                                await deleteSession(ctx, session);
                            }
                        }
                        return;
                    }
                    default:
                        args;
                }
            },
        }),
    };
}
async function getAccountOrThrow(ctx, existingAccountId) {
    const existingAccount = await ctx.db.get(existingAccountId);
    if (existingAccount === null) {
        throw new Error(`Expected an account to exist for ID "${existingAccountId}"`);
    }
    return existingAccount;
}
async function maybeGenerateTokensForSession(ctx, config, userId, sessionId, generateTokens) {
    return {
        userId,
        sessionId,
        tokens: generateTokens
            ? await generateTokensForSession(ctx, config, userId, sessionId)
            : null,
    };
}
async function createNewAndDeleteExistingSession(ctx, config, auth, userId) {
    const existingSessionId = await auth.getSessionId(ctx);
    if (existingSessionId !== null) {
        const existingSession = await ctx.db.get(existingSessionId);
        if (existingSession !== null) {
            await deleteSession(ctx, existingSession);
        }
    }
    return await createSession(ctx, userId, config);
}
async function generateTokensForSession(ctx, config, userId, sessionId) {
    const ids = { userId, sessionId };
    return {
        token: await generateToken(ids, config),
        refreshToken: await createRefreshToken(ctx, sessionId, config),
    };
}
async function verifyCodeOnly(ctx, args, 
/**
 * There are two providers at play:
 * 1. the provider that generated the code
 * 2. the provider the account is tied to.
 * This is because we allow signing into an account
 * via another provider, see {@link signInViaProvider}.
 * This is the first provider.
 */
methodProviderId, getProviderOrThrow, allowExtraProviders, config, sessionId) {
    const { params, verifier } = args;
    const codeHash = await sha256(params.code);
    const verificationCode = await ctx.db
        .query("authVerificationCodes")
        .withIndex("code", (q) => q.eq("code", codeHash))
        .unique();
    if (verificationCode === null) {
        console.error("Invalid verification code");
        return null;
    }
    await ctx.db.delete(verificationCode._id);
    if (verificationCode.verifier !== verifier) {
        console.error("Invalid verifier");
        return null;
    }
    if (verificationCode.expirationTime < Date.now()) {
        console.error("Expired verification code");
        return null;
    }
    const { accountId, emailVerified, phoneVerified } = verificationCode;
    const account = await ctx.db.get(accountId);
    if (account === null) {
        console.error("Account associated with this email has been deleted");
        return null;
    }
    if (methodProviderId !== null &&
        verificationCode.provider !== methodProviderId) {
        console.error(`Invalid provider "${methodProviderId}" for given \`code\`, ` +
            `which was generated by provider "${verificationCode.provider}"`);
        return null;
    }
    // OTP providers perform an additional check against the provided
    // params.
    const methodProvider = getProviderOrThrow(verificationCode.provider, allowExtraProviders);
    if (methodProvider !== null &&
        (methodProvider.type === "email" || methodProvider.type === "phone") &&
        methodProvider.authorize !== undefined) {
        await methodProvider.authorize(args.params, account);
    }
    let userId = account.userId;
    const provider = getProviderOrThrow(account.provider);
    if (!(provider.type === "oauth" || provider.type === "oidc")) {
        ({ userId } = await upsertUserAndAccount(ctx, sessionId, { existingAccount: account }, {
            type: "verification",
            provider,
            profile: {
                ...(emailVerified !== undefined
                    ? { email: emailVerified, emailVerified: true }
                    : {}),
                ...(phoneVerified !== undefined
                    ? { phone: phoneVerified, phoneVerified: true }
                    : {}),
            },
        }, config));
    }
    return { providerAccountId: account.providerAccountId, userId };
}
async function upsertUserAndAccount(ctx, sessionId, account, args, config) {
    const userId = await defaultCreateOrUpdateUser(ctx, sessionId, "existingAccount" in account ? account.existingAccount : null, args, config);
    const accountId = await createOrUpdateAccount(ctx, userId, account, args);
    return { userId, accountId };
}
async function defaultCreateOrUpdateUser(ctx, sessionId, existingAccount, args, config) {
    const existingUserId = existingAccount?.userId ?? null;
    if (config.callbacks?.createOrUpdateUser !== undefined) {
        return await config.callbacks.createOrUpdateUser(ctx, {
            existingUserId,
            ...args,
        });
    }
    const { provider, profile: { emailVerified: profileEmailVerified, phoneVerified: profilePhoneVerified, ...profile }, } = args;
    const emailVerified = profileEmailVerified ??
        ((provider.type === "oauth" || provider.type === "oidc") &&
            provider.allowDangerousEmailAccountLinking !== false);
    const phoneVerified = profilePhoneVerified ?? false;
    const shouldLinkViaEmail = args.shouldLinkViaEmail || emailVerified || provider.type === "email";
    const shouldLinkViaPhone = args.shouldLinkViaPhone || phoneVerified || provider.type === "phone";
    let userId = existingUserId;
    if (existingUserId === null) {
        const existingUserWithVerifiedEmailId = typeof profile.email === "string" && shouldLinkViaEmail
            ? (await uniqueUserWithVerifiedEmail(ctx, profile.email))?._id ?? null
            : null;
        const existingUserWithVerifiedPhoneId = typeof profile.phone === "string" && shouldLinkViaPhone
            ? (await uniqueUserWithVerifiedPhone(ctx, profile.phone))?._id ?? null
            : null;
        // If there is both email and phone verified user
        // already we can't link.
        userId =
            existingUserWithVerifiedEmailId !== null &&
                existingUserWithVerifiedPhoneId !== null
                ? null
                : existingUserWithVerifiedEmailId ?? existingUserWithVerifiedPhoneId;
    }
    const userData = {
        ...(emailVerified ? { emailVerificationTime: Date.now() } : null),
        ...(phoneVerified ? { phoneVerificationTime: Date.now() } : null),
        ...profile,
    };
    if (userId !== null) {
        await ctx.db.patch(userId, userData);
    }
    else {
        userId = await ctx.db.insert("users", userData);
    }
    await config.callbacks?.afterUserCreatedOrUpdated?.(ctx, {
        userId,
        existingUserId,
        ...args,
    });
    return userId;
}
async function createOrUpdateAccount(ctx, userId, account, args) {
    const accountId = "existingAccount" in account
        ? account.existingAccount._id
        : await ctx.db.insert("authAccounts", {
            userId,
            provider: args.provider.id,
            providerAccountId: account.providerAccountId,
            secret: account.secret,
        });
    // This is never used with the default `createOrUpdateUser` implementation,
    // but it is used for manual linking via custom `createOrUpdateUser`:
    if ("existingAccount" in account &&
        account.existingAccount.userId !== userId) {
        await ctx.db.patch(accountId, { userId });
    }
    if (args.profile.emailVerified) {
        await ctx.db.patch(accountId, { emailVerified: args.profile.email });
    }
    if (args.profile.phoneVerified) {
        await ctx.db.patch(accountId, { phoneVerified: args.profile.phone });
    }
    return accountId;
}
async function uniqueUserWithVerifiedEmail(ctx, email) {
    const users = await ctx.db
        .query("users")
        .withIndex("email", (q) => q.eq("email", email))
        .filter((q) => q.neq(q.field("emailVerificationTime"), undefined))
        .take(2);
    return users.length === 1 ? users[0] : null;
}
async function uniqueUserWithVerifiedPhone(ctx, phone) {
    const users = await ctx.db
        .query("users")
        .withIndex("phone", (q) => q.eq("phone", phone))
        .filter((q) => q.neq(q.field("phoneVerificationTime"), undefined))
        .take(2);
    return users.length === 1 ? users[0] : null;
}
async function verify(provider, secret, hash) {
    if (provider.type !== "credentials") {
        throw new Error(`Provider ${provider.id} is not a credentials provider`);
    }
    const verify = provider.crypto?.verifySecret;
    if (verify === undefined) {
        throw new Error(`Provider ${provider.id} does not have a \`crypto.verifySecret\` function`);
    }
    return await verify(secret, hash);
}
async function hash(provider, secret) {
    if (provider.type !== "credentials") {
        throw new Error(`Provider ${provider.id} is not a credentials provider`);
    }
    const hash = provider.crypto?.hashSecret;
    if (hash === undefined) {
        throw new Error(`Provider ${provider.id} does not have a \`crypto.hashSecret\` function`);
    }
    return await hash(secret);
}
/**
 * Use this function from a
 * [`ConvexCredentials`](https://labs.convex.dev/auth/api_reference/providers/ConvexCredentials)
 * provider to create an account and a user with a unique account "id" (OAuth
 * provider ID, email address, phone number, username etc.).
 *
 * @returns user ID if it successfully creates the account
 * or throws an error.
 */
export async function createAccount(ctx, args) {
    const actionCtx = ctx;
    return await actionCtx.runMutation(internal.auth.store, {
        args: {
            type: "createAccountFromCredentials",
            ...args,
        },
    });
}
/**
 * Use this function from a
 * [`ConvexCredentials`](https://labs.convex.dev/auth/api_reference/providers/ConvexCredentials)
 * provider to retrieve a user given the account provider ID and
 * the provider-specific account ID.
 *
 * @returns the retrieved user document, or `null` if there is no account
 * for given account ID or throws if the provided
 * secret does not match.
 */
export async function retrieveAccount(ctx, args) {
    const actionCtx = ctx;
    const result = await actionCtx.runMutation(internal.auth.store, {
        args: {
            type: "retrieveAccountWithCredentials",
            ...args,
        },
    });
    if (typeof result === "string") {
        throw new Error(result);
    }
    return result;
}
/**
 * Use this function to modify the account credentials
 * from a [`ConvexCredentials`](https://labs.convex.dev/auth/api_reference/providers/ConvexCredentials)
 * provider.
 */
export async function modifyAccountCredentials(ctx, args) {
    const actionCtx = ctx;
    return await actionCtx.runMutation(internal.auth.store, {
        args: {
            type: "modifyAccount",
            ...args,
        },
    });
}
/**
 * Use this function to invalidate existing sessions.
 */
export async function invalidateSessions(ctx, args) {
    const actionCtx = ctx;
    return await actionCtx.runMutation(internal.auth.store, {
        args: {
            type: "invalidateSessions",
            ...args,
        },
    });
}
/**
 * Use this function from a
 * [`ConvexCredentials`](https://labs.convex.dev/auth/api_reference/providers/ConvexCredentials)
 * provider to sign in the user via another provider (usually
 * for email verification on sign up or password reset).
 *
 * Returns the user ID if the sign can proceed,
 * or `null`.
 */
export async function signInViaProvider(ctx, provider, args) {
    const result = await signInImpl(ctx, materializeProvider(provider), args, {
        generateTokens: false,
        allowExtraProviders: true,
    });
    return (result.signedIn ?? null);
}
async function signInImpl(ctx, provider, args, options) {
    if (provider === null) {
        if (args.refreshToken) {
            const tokens = await ctx.runMutation(internal.auth.store, {
                args: {
                    type: "refreshSession",
                    refreshToken: args.refreshToken,
                },
            });
            return { signedIn: { tokens } };
        }
        else if (args.params?.code !== undefined) {
            const result = await ctx.runMutation(internal.auth.store, {
                args: {
                    type: "verifyCodeAndSignIn",
                    params: args.params,
                    verifier: args.verifier,
                    generateTokens: true,
                    allowExtraProviders: options.allowExtraProviders,
                },
            });
            return {
                signedIn: result,
            };
        }
        else {
            throw new Error("Cannot sign in: Missing `provider`, `params.code` or `refreshToken`");
        }
    }
    if (provider.type === "email" || provider.type === "phone") {
        if (args.params?.code !== undefined) {
            const result = await ctx.runMutation(internal.auth.store, {
                args: {
                    type: "verifyCodeAndSignIn",
                    params: args.params,
                    provider: provider.id,
                    generateTokens: options.generateTokens,
                    allowExtraProviders: options.allowExtraProviders,
                },
            });
            if (result === null) {
                throw new Error("Could not verify code");
            }
            return {
                signedIn: result,
            };
        }
        const code = provider.generateVerificationToken
            ? await provider.generateVerificationToken()
            : generateRandomString(32, alphabet("0-9", "A-Z", "a-z"));
        const expirationTime = Date.now() +
            (provider.maxAge ?? DEFAULT_EMAIL_VERIFICATION_CODE_DURATION_S) * 1000;
        const identifier = (await ctx.runMutation(internal.auth.store, {
            args: {
                type: "createVerificationCode",
                provider: provider.id,
                accountId: args.accountId,
                email: args.params?.email,
                phone: args.params?.phone,
                code,
                expirationTime,
                allowExtraProviders: options.allowExtraProviders,
            },
        }));
        const destination = await redirectAbsoluteUrl(ctx.auth.config, (args.params ?? {}));
        const verificationArgs = {
            identifier,
            url: setURLSearchParam(destination, "code", code),
            token: code,
            expires: new Date(expirationTime),
        };
        if (provider.type === "email") {
            await provider.sendVerificationRequest({
                ...verificationArgs,
                provider: {
                    ...provider,
                    from: 
                    // Simplifies demo configuration of Resend
                    provider.from === "Auth.js <no-reply@authjs.dev>" &&
                        provider.id === "resend"
                        ? "My App <onboarding@resend.dev>"
                        : provider.from,
                },
                request: new Request("http://localhost"), // TODO: Document
                theme: ctx.auth.config.theme,
            }, 
            // @ts-expect-error Figure out typing for email providers so they can
            // access ctx.
            ctx);
        }
        else if (provider.type === "phone") {
            await provider.sendVerificationRequest({ ...verificationArgs, provider }, ctx);
        }
        return { started: true };
    }
    else if (provider.type === "credentials") {
        const result = await provider.authorize(args.params ?? {}, ctx);
        if (result === null) {
            return { signedIn: null };
        }
        const idsAndTokens = await ctx.runMutation(internal.auth.store, {
            args: {
                type: "signIn",
                userId: result.userId,
                sessionId: result.sessionId,
                generateTokens: options.generateTokens,
            },
        });
        return {
            signedIn: idsAndTokens,
        };
    }
    else if (provider.type === "oauth" || provider.type === "oidc") {
        // We have this action because:
        // 1. We remember the current sessionId if any, so we can link accounts
        // 2. The client doesn't need to know the HTTP Actions URL
        //    of the backend (this simplifies using local backend)
        // 3. The client doesn't need to know which provider is of which type,
        //    and hence which provider requires client-side redirect
        // 4. On mobile the client can complete the flow manually
        if (args.params?.code !== undefined) {
            const result = await ctx.runMutation(internal.auth.store, {
                args: {
                    type: "verifyCodeAndSignIn",
                    params: args.params,
                    verifier: args.verifier,
                    generateTokens: true,
                    allowExtraProviders: options.allowExtraProviders,
                },
            });
            return {
                signedIn: result,
            };
        }
        const redirect = new URL(requireEnv("CONVEX_SITE_URL") + `/api/auth/signin/${provider.id}`);
        const verifier = (await ctx.runMutation(internal.auth.store, {
            args: { type: "verifier" },
        }));
        redirect.searchParams.set("code", verifier);
        if (args.params?.redirectTo !== undefined) {
            if (typeof args.params.redirectTo !== "string") {
                throw new Error(`Expected \`redirectTo\` to be a string, got ${args.params.redirectTo}`);
            }
            redirect.searchParams.set("redirectTo", args.params.redirectTo);
        }
        return { redirect: redirect.toString(), verifier };
    }
    else {
        provider;
        throw new Error(`Provider type ${provider.type} is not supported yet`);
    }
}
async function redirectAbsoluteUrl(config, params) {
    if (params.redirectTo !== undefined) {
        if (typeof params.redirectTo !== "string") {
            throw new Error(`Expected \`redirectTo\` to be a string, got ${params.redirectTo}`);
        }
        const redirectCallback = config.callbacks?.redirect ?? defaultRedirectCallback;
        return await redirectCallback(params);
    }
    return siteUrl();
}
async function defaultRedirectCallback({ redirectTo }) {
    const baseUrl = siteUrl();
    if (redirectTo.startsWith("?") || redirectTo.startsWith("/")) {
        return `${baseUrl}${redirectTo}`;
    }
    if (redirectTo.startsWith(baseUrl)) {
        const after = redirectTo[baseUrl.length];
        if (after === undefined || after === "?" || after === "/") {
            return redirectTo;
        }
    }
    throw new Error(`Invalid \`redirectTo\` ${redirectTo} for configured SITE_URL: ${baseUrl.toString()}`);
}
// Temporary work-around because Convex doesn't support
// schemes other than http and https.
function setURLSearchParam(absoluteUrl, param, value) {
    const pattern = /([^:]+):(.*)/;
    const [, scheme, rest] = absoluteUrl.match(pattern);
    const hasNoDomain = /^\/\/(?:\/|$|\?)/.test(rest);
    const startsWithPath = hasNoDomain && rest.startsWith("///");
    const url = new URL(`http:${hasNoDomain ? "//googblibok" + rest.slice(2) : rest}`);
    url.searchParams.set(param, value);
    const [, , withParam] = url.toString().match(pattern);
    return `${scheme}:${hasNoDomain ? (startsWithPath ? "/" : "") + "//" + withParam.slice(13) : withParam}`;
}
async function isSignInRateLimited(ctx, identifier, config) {
    const state = await getRateLimitState(ctx, identifier, config);
    if (state === null) {
        return false;
    }
    return state.attempsLeft < 1;
}
async function recordFailedSignIn(ctx, identifier, config) {
    const state = await getRateLimitState(ctx, identifier, config);
    if (state !== null) {
        await ctx.db.patch(state.limit._id, {
            attemptsLeft: state.attempsLeft - 1,
            lastAttemptTime: Date.now(),
        });
    }
    else {
        const maxAttempsPerHour = configuredMaxAttempsPerHour(config);
        await ctx.db.insert("authRateLimits", {
            identifier,
            attemptsLeft: maxAttempsPerHour - 1,
            lastAttemptTime: Date.now(),
        });
    }
}
async function resetSignInRateLimit(ctx, identifier) {
    const existingState = await ctx.db
        .query("authRateLimits")
        .withIndex("identifier", (q) => q.eq("identifier", identifier))
        .unique();
    if (existingState !== null) {
        await ctx.db.delete(existingState._id);
    }
}
async function getRateLimitState(ctx, identifier, config) {
    const now = Date.now();
    const maxAttempsPerHour = configuredMaxAttempsPerHour(config);
    const limit = await ctx.db
        .query("authRateLimits")
        .withIndex("identifier", (q) => q.eq("identifier", identifier))
        .unique();
    if (limit === null) {
        return null;
    }
    const elapsed = now - limit.lastAttemptTime;
    const maxAttempsPerMs = maxAttempsPerHour / (60 * 60 * 1000);
    const attempsLeft = Math.min(maxAttempsPerHour, limit.attemptsLeft + elapsed * maxAttempsPerMs);
    return { limit, attempsLeft };
}
function configuredMaxAttempsPerHour(config) {
    return (config.signIn?.maxFailedAttempsPerHour ??
        DEFAULT_MAX_SIGN_IN_ATTEMPS_PER_HOUR);
}
async function generateUniqueVerificationCode(ctx, accountId, provider, code, expirationTime, { email, phone }) {
    const existingCode = await ctx.db
        .query("authVerificationCodes")
        .withIndex("accountId", (q) => q.eq("accountId", accountId))
        .unique();
    if (existingCode !== null) {
        await ctx.db.delete(existingCode._id);
    }
    await ctx.db.insert("authVerificationCodes", {
        accountId,
        provider,
        code: await sha256(code),
        expirationTime,
        emailVerified: email,
        phoneVerified: phone,
    });
}
async function createSession(ctx, userId, config) {
    const expirationTime = Date.now() +
        (config.session?.totalDurationMs ??
            stringToNumber(process.env.AUTH_SESSION_TOTAL_DURATION_MS) ??
            DEFAULT_SESSION_TOTAL_DURATION_MS);
    return await ctx.db.insert("authSessions", { expirationTime, userId });
}
async function deleteSession(ctx, session) {
    await ctx.db.delete(session._id);
    await deleteRefreshTokens(ctx, session._id);
}
async function createRefreshToken(ctx, sessionId, config) {
    const expirationTime = Date.now() +
        (config.session?.inactiveDurationMs ??
            stringToNumber(process.env.AUTH_SESSION_INACTIVE_DURATION_MS) ??
            DEFAULT_SESSION_INACTIVE_DURATION_MS);
    const newRefreshTokenId = await ctx.db.insert("authRefreshTokens", {
        sessionId,
        expirationTime,
    });
    return `${newRefreshTokenId}${REFRESH_TOKEN_DIVIDER}${sessionId}`;
}
async function deleteRefreshTokens(ctx, sessionId) {
    const existingRefreshTokens = await ctx.db
        .query("authRefreshTokens")
        .withIndex("sessionId", (q) => q.eq("sessionId", sessionId))
        .collect();
    for (const refreshTokenDoc of existingRefreshTokens) {
        await ctx.db.delete(refreshTokenDoc._id);
    }
}
async function validateRefreshToken(ctx, refreshTokenId, tokenSessionId) {
    const refreshTokenDoc = await ctx.db.get(refreshTokenId);
    if (refreshTokenDoc === null) {
        console.error("Invalid refresh token");
        return null;
    }
    if (refreshTokenDoc.expirationTime < Date.now()) {
        console.error("Expired refresh token");
        return null;
    }
    if (refreshTokenDoc.sessionId !== tokenSessionId) {
        console.error("Invalid refresh token session ID");
        return null;
    }
    const session = await ctx.db.get(refreshTokenDoc.sessionId);
    if (session === null) {
        console.error("Invalid refresh token session");
        return null;
    }
    if (session.expirationTime < Date.now()) {
        console.error("Expired refresh token session");
        return null;
    }
    return { session, refreshTokenDoc };
}
async function generateToken(args, config) {
    const privateKey = await importPKCS8(requireEnv("JWT_PRIVATE_KEY"), "RS256");
    const expirationTime = new Date(Date.now() + (config.jwt?.durationMs ?? DEFAULT_JWT_DURATION_MS));
    return await new SignJWT({
        sub: args.userId + TOKEN_SUB_CLAIM_DIVIDER + args.sessionId,
    })
        .setProtectedHeader({ alg: "RS256" })
        .setIssuedAt()
        .setIssuer(requireEnv("CONVEX_SITE_URL"))
        .setAudience("convex")
        .setExpirationTime(expirationTime)
        .sign(privateKey);
}
function convertErrorsToResponse(errorStatusCode, action) {
    return async (ctx, request) => {
        try {
            return await action(ctx, request);
        }
        catch (error) {
            if (error instanceof ConvexError) {
                return new Response(null, {
                    status: errorStatusCode,
                    statusText: error.data,
                });
            }
            else {
                logError(error);
                return new Response(null, {
                    status: 500,
                    statusText: "Internal Server Error",
                });
            }
        }
    };
}
function logError(error) {
    console.error(error instanceof Error
        ? error.message + "\n" + error.stack?.replace("\\n", "\n")
        : error);
}
function siteUrl() {
    return requireEnv("SITE_URL").replace(/\/$/, "");
}
function getCookies(request) {
    return parseCookies(request.headers.get("Cookie") ?? "");
}
async function sha256(input) {
    return encodeHex(await rawSha256(new TextEncoder().encode(input)));
}
function stringToNumber(value) {
    return value !== undefined ? Number(value) : undefined;
}
