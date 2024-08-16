/**
 * Configure {@link Password} provider given a {@link PasswordConfig}.
 *
 * The `Password` provider supports the following flows, determined
 * by the `flow` parameter:
 *
 * - `"signUp"`: Create a new account with a password.
 * - `"signIn"`: Sign in with an existing account and password.
 * - `"reset"`: Request a password reset.
 * - `"reset-verification"`: Verify a password reset code and change password.
 * - `"email-verification"`: If email verification is enabled and `code` is
 *    included in params, verify an OTP.
 *
 * ```ts
 * import Password from "@convex-dev/auth/providers/Password";
 * import { convexAuth } from "@convex-dev/auth/server";
 *
 * export const { auth, signIn, signOut, store } = convexAuth({
 *   providers: [Password],
 * });
 * ```
 *
 * @module
 */
import { ConvexCredentials, } from "@convex-dev/auth/providers/ConvexCredentials";
import { createAccount, invalidateSessions, modifyAccountCredentials, retrieveAccount, signInViaProvider, } from "@convex-dev/auth/server";
import { Scrypt } from "lucia";
/**
 * Email and password authentication provider.
 *
 * Passwords are by default hashed using Scrypt from Lucia.
 * You can customize the hashing via the `crypto` option.
 *
 * Email verification is not required unless you pass
 * an email provider to the `verify` option.
 */
export function Password(config = {}) {
    const provider = config.id ?? "password";
    return ConvexCredentials({
        id: "password",
        authorize: async (params, ctx) => {
            const profile = config.profile?.(params, ctx) ?? defaultProfile(params);
            const { email } = profile;
            const flow = params.flow;
            const secret = params.password;
            let account;
            let user;
            if (flow === "signUp") {
                if (secret === undefined) {
                    throw new Error("Missing `password` param for `signUp` flow");
                }
                const created = await createAccount(ctx, {
                    provider,
                    account: { id: email, secret },
                    profile: profile,
                    shouldLinkViaEmail: config.verify !== undefined,
                    shouldLinkViaPhone: false,
                });
                ({ account, user } = created);
            }
            else if (flow === "signIn") {
                if (secret === undefined) {
                    throw new Error("Missing `password` param for `signIn` flow");
                }
                const retrieved = await retrieveAccount(ctx, {
                    provider,
                    account: { id: email, secret },
                });
                if (retrieved === null) {
                    throw new Error("Invalid credentials");
                }
                ({ account, user } = retrieved);
                // START: Optional, support password reset
            }
            else if (flow === "reset") {
                if (!config.reset) {
                    throw new Error(`Password reset is not enabled for ${provider}`);
                }
                const { account } = await retrieveAccount(ctx, {
                    provider,
                    account: { id: email },
                });
                return await signInViaProvider(ctx, config.reset, {
                    accountId: account._id,
                    params,
                });
            }
            else if (flow === "reset-verification") {
                if (!config.reset) {
                    throw new Error(`Password reset is not enabled for ${provider}`);
                }
                if (params.newPassword === undefined) {
                    throw new Error("Missing `newPassword` param for `reset-verification` flow");
                }
                const result = await signInViaProvider(ctx, config.reset, { params });
                if (result === null) {
                    throw new Error("Invalid code");
                }
                const { userId, sessionId } = result;
                const secret = params.newPassword;
                await modifyAccountCredentials(ctx, {
                    provider,
                    account: { id: email, secret },
                });
                await invalidateSessions(ctx, { userId, except: [sessionId] });
                return { userId, sessionId };
                // END
                // START: Optional, email verification during sign in
            }
            else if (flow === "email-verification") {
                if (!config.verify) {
                    throw new Error(`Email verification is not enabled for ${provider}`);
                }
                const { account } = await retrieveAccount(ctx, {
                    provider,
                    account: { id: email },
                });
                return await signInViaProvider(ctx, config.verify, {
                    accountId: account._id,
                    params,
                });
                // END
            }
            else {
                throw new Error("Missing `flow` param, it must be one of " +
                    '"signUp", "signIn", "reset", "reset-verification" or ' +
                    '"email-verification"!');
            }
            // START: Optional, email verification during sign in
            if (config.verify && !account.emailVerified) {
                return await signInViaProvider(ctx, config.verify, {
                    accountId: account._id,
                    params,
                });
            }
            // END
            return { userId: user._id };
        },
        crypto: {
            async hashSecret(password) {
                return await new Scrypt().hash(password);
            },
            async verifySecret(password, hash) {
                return await new Scrypt().verify(hash, password);
            },
        },
        extraProviders: [config.reset, config.verify],
        ...config,
    });
}
function defaultProfile(params) {
    const flow = params.flow;
    if (flow === "signUp" || flow === "reset-verification") {
        const password = (flow === "signUp" ? params.password : params.newPassword);
        if (!password || password.length < 8) {
            throw new Error("Invalid password");
        }
    }
    return {
        email: params.email,
    };
}
