import { ReactNode } from "react";
export declare function ConvexAuthNextjsClientProvider({ apiRoute, serverState, storage, storageNamespace, verbose, children, }: {
    apiRoute?: string;
    serverState: ConvexAuthServerState;
    storage?: "localStorage" | "inMemory";
    storageNamespace?: string;
    verbose?: boolean;
    children: ReactNode;
}): import("react/jsx-runtime").JSX.Element;
export type ConvexAuthServerState = {
    _state: {
        token: string | null;
        refreshToken: string | null;
    };
    _timeFetched: number;
};
