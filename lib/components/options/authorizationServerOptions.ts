import {THAccessTokenAsk, THTokenSave} from "../types";

export type AuthorizationServerOptions = {
    /**
     * When authenticating a request from where to get the access token.
     * It defaults to the authorization header:
     * ```
     * function getToken(req) {
     *     return req.headers['authorization'];
     * }
     * ```
     * @param req The request instance.
     * @return {string|null} The token that the client passed or null if no token found.
     */
    getToken?: (req: any) => string;
    /**
     * After the request is authenticated a payload that contains information about
     * the client and user will be set. This function will decide its location.
     * It defaults to 'payload':
     * ```
     * function setPayloadLocation(req, payload) {
     *     req.payload = payload
     * }
     * ```
     * @param req The request instance.
     * @param payload The payload that will be saved at the request instance.
     */
    setPayloadLocation?: (req: any, payload: object) => void;
    /**
     * The access token's lifetime in seconds.
     *
     * If set to null (not recommended):
     * * The access token will not have an expiration date.
     * * Refresh tokens will not be generated (even if you include the refresh token grant).
     * * To expire the access token, you have to remove it from the database.
     *
     * Defaults to 86400 seconds (1 day).
     */
    accessTokenLifetime?: number | null;
    /**
     * The refresh token's lifetime in seconds.
     *
     * If set to null (not recommended):
     * * The refresh token will never expire.
     * * New refresh tokens will be generated from refresh token grant (it will expire from the database)
     * * To expire the refresh token, you have to remove it from the database.
     *
     * Defaults to 864000 seconds (10 days).
     */
    refreshTokenLifetime?: number | null;
    /**
     * OAuth2 supports a custom error (temporary_unavailable) response instead of the server error 500.
     * If you want to enable this feature you can set this option as true.
     *
     * This option also supports asynchronous calls:
     * ```
     * function isTemporaryUnavailable(req) {
     *     return db.isNotAvailable();
     * }
     * ```
     * @param req The request instance.
     * @return {boolean}
     */
    isTemporaryUnavailable?: boolean | ((req: any) => Promise<boolean>);
    /**
     * When authorizing a client the request can be made from an embedded web view
     * or from a bot. This function will validate if the client asking is valid.
     *
     * It also supports asynchronous calls.
     *
     * By default, this function checks the user agent string to validate the client.
     * It will check for bots and embedded web views. Make note that it will not
     * recognise malicious bots or programs that change their useragent string.
     * @param req The request instance.
     * @returns {boolean} True if request is valid, false otherwise.
     */
    validateRequest?: (req: any) => boolean | Promise<boolean>;
    /**
     * Check if client is allowed to use a specific implementation.
     * For example if the client is confidential you may want to reject implicit grant type.
     *
     * It defaults to 'true':
     * ```
     * function isImplementationAllowed(client_id, impName) {
     *     return true;
     * }
     * ```
     *
     * @param client_id The client's id.
     * @param impName The name of the selected implementation.
     * @param req The request instance.
     * @return {boolean} True if client is allowed, false otherwise.
     */
    isImplementationAllowed?: (client_id: string, impName: string, req: any) => Promise<boolean> | boolean;
    /**
     * The delimiter that will be used to split the scope string.
     * Defaults to ' ' (one space character).
     */
    scopeDelimiter?: string;
    /**
     * The location of the client's credentials (client id & client secret).
     *
     * There are 3 default locations:
     * * header: Basic authorization.
     * * body: Will take fields client_id, client_secret from the request's body.
     * * query: Will take fields client_id, client_secret from the request's query.
     *
     * It defaults to header.
     *
     * It is possible to use a custom location:
     * ```
     * function getClientCredentials(req) {
     *     return {
     *         client_id: req.query,
     *         client_secret: req.body
     *     };
     * }
     * ```
     *
     * If client_id or client_secret is not found, return either null or empty string in their place:
     * ```
     * return {
     *     client_id: req.query || '',
     *     client_secret: req.body || ''
     * };
     * ```
     *
     * @param req The request instance.
     * @return {object} The client_id and client_secret.
     */
    getClientCredentials?: 'header' | 'body' | 'query' | ((req: any) => {
        client_id?: string | null;
        client_secret?: string | null;
    });
    /**
     * When the authorization request is made, the user may have accepted or declined the request.
     *
     * If the user:
     * * Accepts the request, you have to provide an identification.
     * * Declines the request, you have to return null.
     *
     * The user's identification will be included to the tokens' payloads so:
     * * Do not include sensitive information, that you don't want others to know.
     * * The identification must be either a primitive type or valid JSON.
     *
     * It defaults to 'req.user':
     * ```
     * function getUser(req) {
     *     return req.user;
     * }
     * ```
     * @param req The request instance.
     * @return {any} The user's identification or null to deny access.
     */
    getUser?: (req: any) => any;
    /**
     * The error uri that will be passed with the error response.
     */
    errorUri?: string;
    /**
     * During authorization the client will (have to) sent a redirect uri.
     *
     * This function will verify if the redirect uri matches the client's id.
     *
     * Note to always register a redirect uri with your client, to avoid open
     * redirection or other attacks.
     * @param client_id
     * @param redirect_uri
     * @return {boolean} True if client id and redirect uri are valid, false otherwise.
     */
    validateRedirectURI: (client_id: string | null | undefined, redirect_uri: string | null | undefined, req: any) => Promise<boolean>;
    /**
     * This function will check if the scopes sent from the client are valid.
     *
     * Note that it will only check for scope validity and not if client is authorized to use them.
     * If you want to allow specific scopes for each client, you have to add a middleware before reaching
     * the functions and do the checks on your own.
     *
     * ```
     * const acceptedScopes = [ ... ];
     * function validateScopes(scopes) {
     *     return scopes.every(scope => acceptedScopes.includes(scope);
     * }
     * ```
     * If no scopes are sent from the client, an empty array will be passed.
     *
     * This option also supports asynchronous calls.
     *
     * @param scopes The scopes array.
     * @param req The request instance.
     * @return {boolean} True if scopes are valid, false otherwise.
     */
    validateScopes: (scopes: string[], req: any) => Promise<boolean> | boolean;
    /**
     * The authorization server uses JsonWebToken (JWT) to encode the generated tokens.
     * JWT uses a 'secret' to sign the tokens.
     *
     * Note:
     * * The secret must be a secret and never get leaked.
     * * Must be a secure random string at least 32 characters.
     */
    secret: string;
    /**
     * When generating a new access token (and refresh token) this function will be called
     * to save them at the database.
     *
     * Which information must be saved:
     * * accessToken
     * * refreshToken
     *
     * Other information that will be needed for the user (maybe):
     * * accessTokenExpiresAt: a number in seconds since EPOCH that says when the access token expires.
     * * refreshTokenExpiresAt: a number in seconds since EPOCH that says when the refresh token expires.
     * * clientId: The client's identification that the user authorized.
     * * user: The user's identification who authorized the request.
     * * scopes: The scopes the access token has access to.
     *
     * If this function returns false, then the generated tokens will not be sent
     * to the client and will respond with an error 'server_error' message.
     * @param data
     * @param req The request instance, it may be used to pass other data.
     * @return {boolean} True on succeed, false otherwise.
     */
    saveTokens: (data: THTokenSave, req: any) => Promise<boolean>;
    /**
     * When authenticating a request, the library will first do the JWT verification
     * and then ask the database to provide the same token.
     *
     * If the access token has been revoked then return null.
     * @param data The access token alongside some other data that were used when saving the tokens.
     * @param req The request instance.
     * @return {string|null} The access token if it exists, null otherwise.
     */
    getAccessToken: (data: THAccessTokenAsk, req: any) => Promise<string | null | undefined> | string | null | undefined;
};