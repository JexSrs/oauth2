import {OAuth2Error} from "./types";
import {AuthorizationServerOptions} from "./options/authorizationServerOptions";
import EventEmitter from "events";


export interface Implementation {
    /**
     * The name of the implementation. This will be provided to the isImplementationAllowed function.
     * It is not required to be unique.`
     *
     * For example the authorization code flow has two implementations, one that generates the authorization code
     * at the 'authorize' endpoint, and one at the 'token' endpoint.
     */
    name: string;
    /**
     * The endpoint where the implementation will be accessed from:
     * * authorize: The user will need to authorize the request.
     * * token: There is no user interaction, or the user has provided their credentials to the client.
     * * device: There is no user interaction, this endpoint is used for the device flow.
     *
     * Check that will be made before reaching the implementations:
     * * isImplementationAllowed
     *
     * For the authorization endpoint only:
     * * validateRedirectURI
     * * isTemporaryUnavailable
     * * validateRequest
     *
     * The device endpoint only:
     * * validateScopes
     */
    endpoint: 'authorize' | 'token' | 'device';
    /**
     * The response_type (for endpoint 'authorize') or grant_type (for endpoint 'token' and 'device') that the client has to
     * match to access the implementation.
     */
    matchType: string;
    /**
     * This function will be called after all the checks were made.
     * @param data Objects needed for the implementation.
     * @param callback The callback that will provide the answer to the client. In endpoint authorize, state
     *                  will automatically be added, so there is no need to include it in your response.
     * @param eventEmitter The Node.js event emitter that will emit events.
     */
    function: (
        data: {
            /** The request instance, to get any extra information that may be needed. */
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