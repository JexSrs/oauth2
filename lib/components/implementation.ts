import {OAuth2Error} from "./types/types";
import {AuthorizationServerOptions} from "./options/authorizationServerOptions";

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
     */
    endpoint: 'authorize' | 'token';
    /**
     * The response_type (for endpoint 'authorize') or grant_type (for endpoint 'token') that the client has to
     * match to access the implementation.
     */
    matchType: string;
    /**
     * The function that will be called when the matchType is sent by the client.
     * @param req The request instance, to get any existing or extra information that may be needed.
     * @param scopes Only for endpoint authorize, it will validate the scopes using the function isScopesValid
     * @param user Only for endpoint authorize, it will get the user using the function getUser
     * @param callback The callback that will provide the answer to the client. In endpoint authorize, state
     *                  will automatically be added, so there is no need to include it in your response.
     */
    function: (
        req: any,
        serverOpts: AuthorizationServerOptions,
        issueRefreshToken: boolean,
        callback: (response?: object, err?: OAuth2Error & {status?: number; } & object) => void,
        scopes: string[] | undefined,
        user: any | undefined,
    ) => void | Promise<void>;
}