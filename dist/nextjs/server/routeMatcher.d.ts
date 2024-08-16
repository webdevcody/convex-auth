import type Link from "next/link";
import type { NextRequest } from "next/server";
type WithPathPatternWildcard<T> = `${T & string}(.*)`;
type NextTypedRoute<T = Parameters<typeof Link>["0"]["href"]> = T extends string ? T : never;
type Autocomplete<U extends T, T = string> = U | (T & Record<never, never>);
type RouteMatcherWithNextTypedRoutes = Autocomplete<WithPathPatternWildcard<NextTypedRoute> | NextTypedRoute>;
/**
 * See {@link createRouteMatcher} for more information.
 */
export type RouteMatcherParam = Array<RegExp | RouteMatcherWithNextTypedRoutes> | RegExp | RouteMatcherWithNextTypedRoutes | ((req: NextRequest) => boolean);
/**
 * Returns a function that accepts a `Request` object and returns whether the request matches the list of
 * predefined routes that can be passed in as the first argument.
 *
 * You can use glob patterns to match multiple routes or a function to match against the request object.
 * Path patterns and regular expressions are supported, for example: `['/foo', '/bar(.*)'] or `[/^\/foo\/.*$/]`
 * For more information, see: https://github.com/pillarjs/path-to-regexp
 */
export declare const createRouteMatcher: (routes: RouteMatcherParam) => (req: NextRequest) => boolean;
export {};
