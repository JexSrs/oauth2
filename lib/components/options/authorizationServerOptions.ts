import {THAccessTokenAsk, THTokenSave} from "../types";

export type AuthorizationServerOptions = {
    /**
     * Override token location during authentication.
     * Defaults to req.headers['authorization'].
     * @param req The request instance.
     * @return {string} The token that the client passed.
     */
    getToken?: (req: any) => string;
    /**
     * Override payload location (when the verification is complete where to save the verified payload,
     * so it can be accessed later by the app). The payload will be an object that contains {client_id, user, scopes}.
     * Defaults to req.payload.
     * @param req The request instance.
     * @param payload The payload that will be saved at the request instance.
     */
    setPayloadLocation?: (req: any, payload: object) => void;
    /**
     * The access token's lifetime in seconds.
     * If set to null, then the token will never expire and no refresh token will be generated.
     * Defaults to 86400 seconds (1 day).
     */
    accessTokenLifetime?: number | null;
    /**
     * The refresh token's lifetime in seconds.
     * If set to null, then the token will never expire (until it is manually revoked from the database)
     * and no new refresh token will be generated on refresh.
     * Defaults to 864000 seconds (10 days).
     */
    refreshTokenLifetime?: number | null;
    /**
     * If this function return true, it will abort the authorization requests
     * with the justification of temporary unavailable.
     * Can also be an asynchronous function in case you want to ask a remote service.
     * Defaults to false.
     * @return {boolean} true to abort, false otherwise.
     */
    isTemporaryUnavailable?: boolean | ((req: any) => Promise<boolean>);
    /**
     * If the request was made using an embedded web view the request will be rejected.
     * The agent header will be used to verify the browser that makes the request.
     * Defaults to true.
     */
    rejectEmbeddedWebViews?: boolean;
    /**
     * Checks if grant type is allowed for a specific client during authorization.
     * For example if the client is confidential you may want to reject implicit grant type.
     * Defaults to true.
     * @param client_id
     * @return {boolean} true if it is allowed, false otherwise.
     */
    isGrantTypeAllowed?: (client_id: string, type: string) => Promise<boolean> | boolean;
    /**
     * The delimiter that will be used to split the scope string.
     * Defaults to ' ' (one space character).
     */
    scopeDelimiter?: string;



    /**
     * Validate that the redirect uri that was passed during authorization is
     * registered matches the client's redirect uris.
     * @param client_id
     * @param redirect_uri
     * @return {boolean} true if validation passes, false otherwise.
     */
    validateRedirectURI: (client_id: string, redirect_uri: string) => Promise<boolean>;
    /**
     * Get an identification of the user that was authenticated in this request.
     * This will be included in payloads so do not add sensitive data.
     * Return null, if the user did not authorize the request.
     * @param req The request instance.
     * @return {string | object | number | (string | object | number | boolean)[] | null} The user's identification.
     */
    getUser: (req: any) => string | object | number | (string | object | number | boolean | null)[] | null;
    /**
     * A function that asks if the passed scopes are valid. Not if permitted, this will be handled by the user.
     * If no scopes where send with the request then this function will be called once with an empty array.
     * @param scopes
     * @return {boolean} true if scope is valid, false otherwise
     */
    isScopesValid: (scopes: string[]) => (Promise<boolean> | boolean);
    /**
     * The token secret that will be used to sign the tokens using JSONWebToken (JWT).
     */
    secret: string;
    /**
     * The function that will load the accessToken from database.
     * @param data
     * @return {string|null} The access token if it exists.
     */
    getAccessToken: (data: THAccessTokenAsk) => Promise<string | null | undefined> | string | null | undefined;
    /**
     * The error uri that will be passed in case of error.
     */
    errorUri?: string;
    /**
     * The function that will save the access and refresh tokens to the database.
     * @param data
     * @return {boolean} True on succeed, false otherwise.
     */
    saveTokens: (data: THTokenSave) => Promise<boolean>;
};