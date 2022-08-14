import {OAuth2Error} from "./types";
import {AuthorizationServerOptions} from "./authorizationServerOptions.js";
import EventEmitter from "events";

type FlowReturn = object | (OAuth2Error & { status?: number; });

export interface Flow {
    name: string;
    endpoint: 'authorize' | 'token' | 'device_authorization';
    matchType: string;
    function: (
        data: {
            /** The request instance, to get any extra information that may be needed. */
            req: any;
            /** The authorization server's options that was passed while creating the server. */
            serverOpts: Required<AuthorizationServerOptions>;
            /** Whether a refresh token will be issued. */
            issueRefreshToken: boolean;
            /** The authenticated client id. */
            clientId: string;
            /** Only if the flow is called by the 'authorize' function, the scopes that was requested. */
            scopes?: string[];
            /** Only if the flow is called by the 'authorize' function, the user's identification. */
            user?: any;
        },
        eventEmitter: EventEmitter
    ) => Promise<FlowReturn> | FlowReturn;
}