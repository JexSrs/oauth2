import {OAuth2Error} from "./types";
import {AuthorizationServerOptions} from "./options/authorizationServerOptions";
import EventEmitter from "events";


export interface Implementation {
    /**
     * The name of the implementation. This will be used for error handling,
     * and it is not necessary to be unique.
     */
    name: string;
    /**
     * The endpoint where the implementation will be accessed.
     * * authorize: The user will need to authorize the request before reaching the implementation.
     * * token: There is no user interaction, or the user has provided their credentials to the client.
     * * device: There is no user interaction, this endpoint will be used for the device flow.
     *
     * The authorization endpoint will make the following checks:
     * * validateRedirectURI
     * * isTemporaryUnavailable
     * * rejectEmbeddedWebViews
     * * isGrantTypeAllowed
     * * isScopesValid
     *
     * The device endpoint will make the following checks:
     * * isScopesValid
     */
    endpoint: 'authorize' | 'token' | 'device';
    /**
     * The response_type (for endpoint 'authorize') or grant_type (for endpoint 'token' and 'device') that the client has to
     * match to access the implementation.
     */
    matchType: string;
    /**
     * The function that will be called when the matchType is sent by the client.
     * @param data Objects needed for the implementation.
     * @param callback The callback that will provide the answer to the client. In endpoint authorize, state
     *                  will automatically be added, so there is no need to include it in your response.
     */
    function: (
        data: {
            /** The request instance, to get any existing or extra information that may be needed. */
            req: any;
            /** The authorization server's options that was passed while creating the server. */
            serverOpts: Required<AuthorizationServerOptions>,
            /** Whether a refresh token will be issued. */
            issueRefreshToken: boolean,
            /** Only for endpoint 'authorize' & 'device', the scopes that was requested. */
            scopes?: string[],
            /** Only for endpoint 'authorize', the user's identification. */
            user?: any,
        },
        callback: (response?: object, err?: OAuth2Error & {status?: number; } & object) => void,
        eventEmitter: EventEmitter
    ) => void | Promise<void>;
}