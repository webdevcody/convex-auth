import { FunctionReference, OptionalRestArgs } from "convex/server";
export type AuthClient = {
    authenticatedCall<Action extends FunctionReference<"action", "public">>(action: Action, ...args: OptionalRestArgs<Action>): Promise<Action["_returnType"]>;
    unauthenticatedCall<Action extends FunctionReference<"action", "public">>(action: Action, ...args: OptionalRestArgs<Action>): Promise<Action["_returnType"]>;
    verbose: boolean | undefined;
};
