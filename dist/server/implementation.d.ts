import { Auth, DocumentByName, GenericActionCtx, GenericDataModel, HttpRouter, WithoutSystemFields } from "convex/server";
import { GenericId, Value } from "convex/values";
import { GenericDoc } from "./convex_types.js";
import { AuthProviderConfig, ConvexAuthConfig, GenericActionCtxWithAuthConfig } from "./types.js";
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
export declare const authTables: {
    /**
     * Users.
     */
    users: import("convex/server").TableDefinition<import("convex/values").VObject<{
        name?: string | undefined;
        image?: string | undefined;
        email?: string | undefined;
        emailVerificationTime?: number | undefined;
        phone?: string | undefined;
        phoneVerificationTime?: number | undefined;
        isAnonymous?: boolean | undefined;
    }, {
        name: import("convex/values").VString<string | undefined, "optional">;
        image: import("convex/values").VString<string | undefined, "optional">;
        email: import("convex/values").VString<string | undefined, "optional">;
        emailVerificationTime: import("convex/values").VFloat64<number | undefined, "optional">;
        phone: import("convex/values").VString<string | undefined, "optional">;
        phoneVerificationTime: import("convex/values").VFloat64<number | undefined, "optional">;
        isAnonymous: import("convex/values").VBoolean<boolean | undefined, "optional">;
    }, "required", "name" | "image" | "email" | "emailVerificationTime" | "phone" | "phoneVerificationTime" | "isAnonymous">, {
        email: ["email", "_creationTime"];
        phone: ["phone", "_creationTime"];
    }, {}, {}>;
    /**
     * Sessions.
     * A single user can have multiple active sessions.
     * See [Session document lifecycle](https://labs.convex.dev/auth/advanced#session-document-lifecycle).
     */
    authSessions: import("convex/server").TableDefinition<import("convex/values").VObject<{
        userId: GenericId<"users">;
        expirationTime: number;
    }, {
        userId: import("convex/values").VId<GenericId<"users">, "required">;
        expirationTime: import("convex/values").VFloat64<number, "required">;
    }, "required", "userId" | "expirationTime">, {
        userId: ["userId", "_creationTime"];
    }, {}, {}>;
    /**
     * Accounts. An account corresponds to
     * a single authentication provider.
     * A single user can have multiple accounts linked.
     */
    authAccounts: import("convex/server").TableDefinition<import("convex/values").VObject<{
        secret?: string | undefined;
        emailVerified?: string | undefined;
        phoneVerified?: string | undefined;
        userId: GenericId<"users">;
        provider: string;
        providerAccountId: string;
    }, {
        userId: import("convex/values").VId<GenericId<"users">, "required">;
        provider: import("convex/values").VString<string, "required">;
        providerAccountId: import("convex/values").VString<string, "required">;
        secret: import("convex/values").VString<string | undefined, "optional">;
        emailVerified: import("convex/values").VString<string | undefined, "optional">;
        phoneVerified: import("convex/values").VString<string | undefined, "optional">;
    }, "required", "userId" | "provider" | "providerAccountId" | "secret" | "emailVerified" | "phoneVerified">, {
        userIdAndProvider: ["userId", "provider", "_creationTime"];
        accountIdAndProvider: ["providerAccountId", "provider", "_creationTime"];
    }, {}, {}>;
    /**
     * Refresh tokens.
     * Each session has only a single refresh token
     * valid at a time. Refresh tokens are rotated
     * and reuse is not allowed.
     */
    authRefreshTokens: import("convex/server").TableDefinition<import("convex/values").VObject<{
        expirationTime: number;
        sessionId: GenericId<"authSessions">;
    }, {
        sessionId: import("convex/values").VId<GenericId<"authSessions">, "required">;
        expirationTime: import("convex/values").VFloat64<number, "required">;
    }, "required", "expirationTime" | "sessionId">, {
        sessionId: ["sessionId", "_creationTime"];
    }, {}, {}>;
    /**
     * Verification codes:
     * - OTP tokens
     * - magic link tokens
     * - OAuth codes
     */
    authVerificationCodes: import("convex/server").TableDefinition<import("convex/values").VObject<{
        emailVerified?: string | undefined;
        phoneVerified?: string | undefined;
        verifier?: string | undefined;
        expirationTime: number;
        provider: string;
        accountId: GenericId<"authAccounts">;
        code: string;
    }, {
        accountId: import("convex/values").VId<GenericId<"authAccounts">, "required">;
        provider: import("convex/values").VString<string, "required">;
        code: import("convex/values").VString<string, "required">;
        expirationTime: import("convex/values").VFloat64<number, "required">;
        verifier: import("convex/values").VString<string | undefined, "optional">;
        emailVerified: import("convex/values").VString<string | undefined, "optional">;
        phoneVerified: import("convex/values").VString<string | undefined, "optional">;
    }, "required", "expirationTime" | "provider" | "emailVerified" | "phoneVerified" | "accountId" | "code" | "verifier">, {
        accountId: ["accountId", "_creationTime"];
        code: ["code", "_creationTime"];
    }, {}, {}>;
    /**
     * PKCE verifiers for OAuth.
     */
    authVerifiers: import("convex/server").TableDefinition<import("convex/values").VObject<{
        sessionId?: GenericId<"authSessions"> | undefined;
        signature?: string | undefined;
    }, {
        sessionId: import("convex/values").VId<GenericId<"authSessions"> | undefined, "optional">;
        signature: import("convex/values").VString<string | undefined, "optional">;
    }, "required", "sessionId" | "signature">, {
        signature: ["signature", "_creationTime"];
    }, {}, {}>;
    /**
     * Rate limits for OTP and password sign-in.
     */
    authRateLimits: import("convex/server").TableDefinition<import("convex/values").VObject<{
        identifier: string;
        lastAttemptTime: number;
        attemptsLeft: number;
    }, {
        identifier: import("convex/values").VString<string, "required">;
        lastAttemptTime: import("convex/values").VFloat64<number, "required">;
        attemptsLeft: import("convex/values").VFloat64<number, "required">;
    }, "required", "identifier" | "lastAttemptTime" | "attemptsLeft">, {
        identifier: ["identifier", "_creationTime"];
    }, {}, {}>;
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
export declare function convexAuth(config_: ConvexAuthConfig): {
    /**
     * Helper for configuring HTTP actions and accessing
     * the current user and session ID.
     */
    auth: {
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
        getUserId: (ctx: {
            auth: Auth;
        }) => Promise<GenericId<"users"> | null>;
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
        getSessionId: (ctx: {
            auth: Auth;
        }) => Promise<GenericId<"authSessions"> | null>;
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
        addHttpRoutes: (http: HttpRouter) => void;
    };
    /**
     * Action called by the client to sign the user in.
     *
     * Also used for refreshing the session.
     */
    signIn: import("convex/server").RegisteredAction<"public", {
        provider?: string | undefined;
        verifier?: string | undefined;
        refreshToken?: string | undefined;
        params?: any;
    }, Promise<{
        redirect: string;
        verifier: GenericId<"authVerifiers">;
        started?: undefined;
        tokens?: undefined;
    } | {
        started: boolean;
        redirect?: undefined;
        verifier?: undefined;
        tokens?: undefined;
    } | {
        tokens: {
            token: string;
            refreshToken: string;
        } | null;
        redirect?: undefined;
        verifier?: undefined;
        started?: undefined;
    }>>;
    /**
     * Action called by the client to invalidate the current session.
     */
    signOut: import("convex/server").RegisteredAction<"public", {}, Promise<void>>;
    /**
     * Internal mutation used by the library to read and write
     * to the database during signin and signout.
     */
    store: import("convex/server").RegisteredMutation<"internal", {
        args: {
            sessionId?: GenericId<"authSessions"> | undefined;
            type: "signIn";
            userId: GenericId<"users">;
            generateTokens: boolean;
        } | {
            type: "signOut";
        } | {
            type: "refreshSession";
            refreshToken: string;
        } | {
            provider?: string | undefined;
            verifier?: string | undefined;
            type: "verifyCodeAndSignIn";
            generateTokens: boolean;
            params: any;
            allowExtraProviders: boolean;
        } | {
            type: "verifier";
        } | {
            type: "verifierSignature";
            verifier: string;
            signature: string;
        } | {
            type: "userOAuth";
            provider: string;
            providerAccountId: string;
            signature: string;
            profile: any;
        } | {
            email?: string | undefined;
            phone?: string | undefined;
            accountId?: GenericId<"authAccounts"> | undefined;
            type: "createVerificationCode";
            expirationTime: number;
            provider: string;
            code: string;
            allowExtraProviders: boolean;
        } | {
            shouldLinkViaEmail?: boolean | undefined;
            shouldLinkViaPhone?: boolean | undefined;
            type: "createAccountFromCredentials";
            provider: string;
            profile: any;
            account: {
                secret?: string | undefined;
                id: string;
            };
        } | {
            type: "retrieveAccountWithCredentials";
            provider: string;
            account: {
                secret?: string | undefined;
                id: string;
            };
        } | {
            type: "modifyAccount";
            provider: string;
            account: {
                id: string;
                secret: string;
            };
        } | {
            except?: GenericId<"authSessions">[] | undefined;
            type: "invalidateSessions";
            userId: GenericId<"users">;
        };
    }, Promise<string | void | {
        token: string;
        refreshToken: string;
    } | {
        userId: GenericId<"users">;
        sessionId: GenericId<"authSessions">;
        tokens: {
            token: string;
            refreshToken: string;
        } | null;
    } | {
        userId: GenericId<"users">;
        sessionId: GenericId<"authSessions">;
        account?: undefined;
        user?: undefined;
    } | {
        account: {
            _id: GenericId<"authAccounts">;
            _creationTime: number;
            secret?: string | undefined;
            emailVerified?: string | undefined;
            phoneVerified?: string | undefined;
            userId: GenericId<"users">;
            provider: string;
            providerAccountId: string;
        } | null;
        user: {
            _id: GenericId<"users">;
            _creationTime: number;
            name?: string | undefined;
            image?: string | undefined;
            email?: string | undefined;
            emailVerificationTime?: number | undefined;
            phone?: string | undefined;
            phoneVerificationTime?: number | undefined;
            isAnonymous?: boolean | undefined;
        } | null;
        userId?: undefined;
        sessionId?: undefined;
    } | null>>;
};
/**
 * Use this function from a
 * [`ConvexCredentials`](https://labs.convex.dev/auth/api_reference/providers/ConvexCredentials)
 * provider to create an account and a user with a unique account "id" (OAuth
 * provider ID, email address, phone number, username etc.).
 *
 * @returns user ID if it successfully creates the account
 * or throws an error.
 */
export declare function createAccount<DataModel extends GenericDataModel = GenericDataModel>(ctx: GenericActionCtx<DataModel>, args: {
    /**
     * The provider ID (like "password"), used to disambiguate accounts.
     *
     * It is also used to configure account secret hashing via the provider's
     * `crypto` option.
     */
    provider: string;
    account: {
        /**
         * The unique external ID for the account, for example email address.
         */
        id: string;
        /**
         * The secret credential to store for this account, if given.
         */
        secret?: string;
    };
    /**
     * The profile data to store for the user.
     * These must fit the `users` table schema.
     */
    profile: WithoutSystemFields<DocumentByName<DataModel, "users">>;
    /**
     * If `true`, the account will be linked to an existing user
     * with the same verified email address.
     * This is only safe if the returned account's email is verified
     * before the user is allowed to sign in with it.
     */
    shouldLinkViaEmail?: boolean;
    /**
     * If `true`, the account will be linked to an existing user
     * with the same verified phone number.
     * This is only safe if the returned account's phone is verified
     * before the user is allowed to sign in with it.
     */
    shouldLinkViaPhone?: boolean;
}): Promise<{
    account: GenericDoc<DataModel, "authAccounts">;
    user: GenericDoc<DataModel, "users">;
}>;
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
export declare function retrieveAccount<DataModel extends GenericDataModel = GenericDataModel>(ctx: GenericActionCtx<DataModel>, args: {
    /**
     * The provider ID (like "password"), used to disambiguate accounts.
     *
     * It is also used to configure account secret hashing via the provider's
     * `crypto` option.
     */
    provider: string;
    account: {
        /**
         * The unique external ID for the account, for example email address.
         */
        id: string;
        /**
         * The secret that should match the stored credential, if given.
         */
        secret?: string;
    };
}): Promise<{
    account: GenericDoc<DataModel, "authAccounts">;
    user: GenericDoc<DataModel, "users">;
}>;
/**
 * Use this function to modify the account credentials
 * from a [`ConvexCredentials`](https://labs.convex.dev/auth/api_reference/providers/ConvexCredentials)
 * provider.
 */
export declare function modifyAccountCredentials<DataModel extends GenericDataModel = GenericDataModel>(ctx: GenericActionCtx<DataModel>, args: {
    /**
     * The provider ID (like "password"), used to disambiguate accounts.
     *
     * It is also used to configure account secret hashing via the `crypto` option.
     */
    provider: string;
    account: {
        /**
         * The unique external ID for the account, for example email address.
         */
        id: string;
        /**
         * The new secret credential to store for this account.
         */
        secret: string;
    };
}): Promise<GenericDoc<DataModel, "users">>;
/**
 * Use this function to invalidate existing sessions.
 */
export declare function invalidateSessions<DataModel extends GenericDataModel = GenericDataModel>(ctx: GenericActionCtx<DataModel>, args: {
    userId: GenericId<"users">;
    except?: GenericId<"authSessions">[];
}): Promise<GenericDoc<DataModel, "users">>;
/**
 * Use this function from a
 * [`ConvexCredentials`](https://labs.convex.dev/auth/api_reference/providers/ConvexCredentials)
 * provider to sign in the user via another provider (usually
 * for email verification on sign up or password reset).
 *
 * Returns the user ID if the sign can proceed,
 * or `null`.
 */
export declare function signInViaProvider<DataModel extends GenericDataModel = GenericDataModel>(ctx: GenericActionCtxWithAuthConfig<DataModel>, provider: AuthProviderConfig, args: {
    accountId?: GenericId<"authAccounts">;
    params?: Record<string, Value | undefined>;
}): Promise<{
    userId: GenericId<"users">;
    sessionId: GenericId<"authSessions">;
} | null>;
