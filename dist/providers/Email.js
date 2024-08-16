/**
 * Simplifies creating custom email providers, such as for sending OTPs.
 *
 * @module
 */
/**
 * Email providers send a token to the user's email address
 * for sign-in.
 *
 * When you use this function to create your config, by default it
 * checks that there is an `email` field during token verification
 * that matches the `email` used during the initial `signIn` call.
 *
 * If you want the "magic link behavior", where only the token is needed,
 * you can override the `authorize` method to skip the check:
 *
 * ```ts
 * import Email from "@convex-dev/auth/providers/Email";
 * import { convexAuth } from "@convex-dev/auth/server";
 *
 * export const { auth, signIn, signOut, store } = convexAuth({
 *   providers: [
 *     Email({ authorize: undefined }),
 *   ],
 * });
 * ```
 *
 * Make sure the token has high enough entropy to be secure.
 */
export function Email(config) {
    return {
        id: "email",
        type: "email",
        name: "Email",
        from: "Auth.js <no-reply@authjs.dev>",
        maxAge: 60 * 60, // 1 hour
        authorize: async (params, account) => {
            if (typeof params.email !== "string") {
                throw new Error("Token verification requires an `email` in params of `signIn`.");
            }
            if (account.providerAccountId !== params.email) {
                throw new Error("Short verification code requires a matching `email` " +
                    "in params of `signIn`.");
            }
        },
        sendVerificationRequest: config.sendVerificationRequest,
        options: config,
    };
}
