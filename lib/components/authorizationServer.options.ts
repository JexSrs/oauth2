import {PlusUN, RevocationAsk, THAccessTokenAsk, THRefreshTokenAsk, THTokenSave} from "./general.types.js";
import {MetadataOptions} from "./metadata.types.js";

export type AuthorizationServerOptions = {
    // * [RFC8414](https://datatracker.ietf.org/doc/html/rfc8414): OAuth 2.0 Authorization Server Metadata
    //
    // ### `metadata`
    // Used by the
    // [`metadata`](functions_and_endpoints.md#metadata)
    // function to inquire a set of information about the authorization server.
    //
    //
    // ## Metadata
    // The `metadata` function is assigned to the `metatdata` endpoint
    // The `metadata` endpoint is used by the clients to access information about
    // the authorization server such the authorization/token/revocation url.
    //
    // ### How to use
    // The `metadata` function is called directly.
    // ```javascript
    // app.get('/api/oauth/v2/metadata', authServer.metadata());
    // ```
    //
    // ### Break down
    // The `metadata` function will follow the order below:
    // * Create the metadata from [`metadata`](./authorization_server.md#metadata) option.
    //
    //
    // /**
    //  * Used by the `metadata` function to inquire a set of information about
    //  * the authorization server.
    //  */
    // metadata?: MetadataOptions;
    /**
     * Used by the `authenticate` function to inquire about the
     * location of the access token. It defaults to the authorization header.
     * @param req The request instance.
     * @return {string|null} The token that the client passed or null if no token found.
     */
    getToken?: (req: any) => string;
    /**
     * Used by the `authenticate` function to inquire about the
     * where to save the "payload" if the authentication succeeds.
     * @param req The request instance.
     * @param payload The payload that will be saved at the request instance.
     */
    setPayloadLocation?: (req: any, payload: object) => void;
    /**
     * The time in seconds where the access token will be valid. It defaults to `86400 sec` = 1 day.
     *
     * In case you want an access token to never expire you can set this field to `null`.
     * Although it is not recommended, if you still want to never expire an access token,
     * take note of the following:
     * * The access will not have an expiration date. Meaning the JWT expiration check will always pass.
     * * Refresh tokens **will be** generated if you include the `refreshToken` flow.
     * * The only way to expire an access token is to remove from the database.
     */
    accessTokenLifetime?: number | null;
    /**
     * The time in seconds where the refresh token will be valid. It defaults to `864000 sec` = 10 days.
     *
     * In case you want a refresh token to never expire you can set this field to `null`.
     * Although it is not recommended, if you still want to never expire a refresh token,
     * take note of the following:
     * * The refresh token will not have an expiration date. Meaning the JWT expiration check will always pass.
     * * New refresh tokens will be generated from `refreshToken` flow, and it will replace the old refresh token.
     * * The only way to expire a refresh token is to remove from the database.
     */
    refreshTokenLifetime?: number | null;
    /**
     * Used by the `authorize` function to check
     * if the server is undergoing maintenance, or is otherwise unavailable, the error code
     * `temporarily_unavailable`can be returned instead of responding with a 503 Service Unavailable
     * status code. It defaults to `false`.
     *
     * This option also supports asynchronous calls.
     * @param req The request instance.
     * @return {boolean}
     */
    isTemporarilyUnavailable?: boolean
        | ((req: any) => boolean)
        | ((req: any) => Promise<boolean>);
    /**
     * Used by the [`authorize`](../functions_and_endpoints.md#authorize) function to validate a request.
     * By default, it will verify using the `user-agent` header if the request is from an embedded
     * WebView or from a bot and reject the request.
     *
     * This option also supports asynchronous calls,
     * Make note that it will not recognise malicious bots or programs that change their useragent string.
     * @param req The request instance.
     * @returns {boolean} True if request is valid, false otherwise.
     */
    validateRequest?: ((req: any) => boolean) | ((req: any) => Promise<boolean>);
    /**
     * Used by the `authorize`, `token` and `device` functions to check if the
     * requested flow is allowed to be used from the client requesting.
     * It defaults to `true` for all clients.
     *
     * This option also supports asynchronous calls.
     * @param client_id The client's id.
     * @param flowName The name of the selected flow.
     * @param req The request instance.
     * @return {boolean} True if client is allowed, false otherwise.
     */
    isFlowAllowed?: ((client_id: any, flowName: string, req: any) => boolean)
        | ((client_id: any, flowName: string, req: any) => Promise<boolean>);
    /**
     * The delimiter that will be used to split the scope string.
     * It defaults to one space character (`' '`).
     */
    scopeDelimiter?: string;
    /**
     * Used by the `token`, `device`, `introspection`, `revocation` functions and
     * `Authorization Code`, `Client Credentials`, `Refresh Token`, `Resource Owner Credentials`
     * flows to inquire the location of the client's credentials (`client id` & `client secret`).
     *
     * These credentials will be called later by the `validateClient` option.
     *
     * There are 3 default locations:
     * * `header`: Basic authorization.
     * * `body`: Will take fields `client_id`, `client_secret` from the request's body.
     * * `query`: Will take fields `client_id`, `client_secret` from the request's query.
     *
     * It defaults to `header`.
     *
     * It is possible to use a custom location:
     * ```javascript
     * function getClientCredentials(req) {
     *     return {
     *         client_id: req.query.client_id,
     *         client_secret: req.body.client_secret
     *     };
     * }
     * ```
     *
     * If `client id` or `client secret` is not found, return either `null`, `undefined`
     * or an empty string (`falsy`) in their place.
     * @param req The request instance.
     * @return {object} The client_id and client_secret.
     */
    getClientCredentials?: 'header' | 'body' | 'query' | ((req: any) => {
        client_id: any;
        client_secret: any;
    });
    /**
     * Used by the `authorize` function and `Device Authorization` flow to inquire about
     * the user's identification.
     *
     * At the `authorize` function you have to provide the user's unique identification who authorized
     * a client from your `front-end` authorization page. If the authorization was declined
     * do not stop the flow and just return `null` (`oauth2` library will handle the rejection for you).
     *
     * At the `Device Authorization` flow you have to provide the user's unique identification who authorized
     * a client from your `front-end` device authorization page. If the authorization was declined
     * do not stop the flow and just return `null` (`oauth2` library will handle the rejection for you).
     *
     * Make not that the user's identification will be included to the JWT so:
     * * do not include sensitive information, that you don't want others to know.
     * * the identification must be either a primitive type or valid JSON.
     *
     * It defaults to `req.user`:
     * ```javascript
     * getUser: req => req.user;
     * ```
     * @param req The request instance.
     * @return {any} The user's identification or null to deny access.
     */
    getUser?: (req: any) => any;
    /**
     * This field is used by all the flows and endpoints and can be overridden from the flows options.
     *
     * The server can also return a URL to a human-readable web page with information about the error.
     * This is intended for the developer to get more information about the error, and is not meant
     * to be displayed to the end user.
     */
    errorUri?: string;
    /**
     * Used by all the flows and to inquire about where the generated tokens are meant to be used.
     * It defaults to `issuer`, which specifies that is meant to be used only to authorization server.
     *
     * This option also supports asynchronous calls.
     * @param client_id The client id of the authenticated client.
     * @param req The request instance.
     */
    audience?: string
        | ((client_id: any, scopes: string[], req: any) => string)
        | ((client_id: any, scopes: string[], req: any) => Promise<string>);
    /**
     * Used by the `introspection`, `authenticate`
     * functions to inquire if an access token should be deleted after it is used.
     * It defaults to `false`.
     */
    deleteAfterUse?: boolean;
    /**
     * Used by the `authorize` function to check if the authorization endpoint can be called
     * from the `POST` method (aside the `GET` method). It defaults to `false`.
     */
    allowAuthorizeMethodPOST?: boolean;
    /**
     * Used by the `authorize`, `token`, `deviceAuthorization`
     * functions to inquire if a refresh token will be generated for this client.
     * It will not generate a refresh token if the `Refresh Token` flow is not used.
     * It defaults to `true` for all clients.
     *
     * This option also supports asynchronous calls.
     */
    issueRefreshTokenForThisClient?: ((client_id: any, req: any) => boolean)
        | ((client_id: any, req: any) => Promise<boolean>);
    /**
     * Used by the `introspection`, `revocation` functions and
     * `Authorization Code` `Client Credentials`, `Device Authorization`,
     * `Refresh Token`, `Resource Owner Credentials` flows inquire if the
     * credentials that was sent from the client are valid.
     *
     * The parameters `client_id` & `client_secret` are coming from the result of the
     * `getClientCredentials`. In some cases like the `Device Authorization`
     * flow or when the client is public the `client_secret` will not be present.
     *
     * This option also supports asynchronous calls.
     * @param client_id The client's id.
     * @param client_secret The client's secret. It will be omitted if the user is e.x. a public client.
     * @param req The request instance.
     * @return {boolean} True if validation succeeds, false otherwise.
     */
    validateClient: ((client_id: any, client_secret: any, req: any) => boolean)
        | ((client_id: any, client_secret: any, req: any) => Promise<boolean>);
    /**
     * Used by the `authorize` function to validate the client's id and redirect
     * uri. It is highly recommended to pre-register the redirect uris for your
     * client to avoid open redirection or other attacks. If the redirect uri is
     * not present you should return `falsy`.
     *
     * If the redirect uri is registered you can either return `true` or the redirect
     * uri itself. In the later case the `oauth2` library will check if the redirect uri
     * is the exact match of the one send by the client (in case of localhost it will
     * skip the port checking).
     *
     * This option also supports asynchronous calls.
     * @param client_id
     * @param redirect_uri
     * @return {boolean} True if client id and redirect uri are valid, false otherwise.
     */
    validateRedirectURI: ((client_id: any, redirect_uri: PlusUN<string>, req: any) => boolean | string)
        | ((client_id: any, redirect_uri: PlusUN<string>, req: any) => Promise<boolean | string>);
    /**
     * Used by the `authorize` and `device` function to inquire if the
     * scopes send by the client are valid. If the client does not
     * send a scope string an empty array will be passed.
     *
     * In case you want to proceed with the request but omit invalid scopes you can return
     * a subset of the requested scopes. It is not mandatory to return a subset of the existing
     * scopes, but it is highly recommended.
     *
     * You should return `false` if the scopes refer to different resource servers.
     *
     * This option also supports asynchronous calls.
     * @param scopes The scopes array.
     * @param req The request instance.
     * @return {boolean} True if scopes are valid, false otherwise.
     */
    validateScopes: ((scopes: string[], req: any) => boolean | string[])
        | ((scopes: string[], req: any) => Promise<boolean | string[]>);
    /**
     * The `AuthorizationServer` uses JsonWebToken (JWT) for generating any kind of tokens.
     * At JWT, `issuer` is the party that created the token and signed it with its private key
     * (`secret`). In this case the `AuthorizationServer` is the one who issues the tokens.
     * In most cases the `issuer` option is the `AuthorizationServer`'s HTTPS base URL.
     */
    secret: string;
    /**
     * The base URL of your authorization server. It will be used as the issuer in all generated
     * tokens and will be appended to the metadata endpoints.
     */
    baseUrl: string;
    /**
     * Used by all the flows to save the generated tokens to the database.
     * It should always return `true` unless the database did not save the tokens,
     * in that case you must return `false`.
     *
     * This function also supports async calls.
     * @param data
     * @param req The request instance, it may be used to pass other data.
     * @return {boolean} True on succeed, false otherwise.
     */
    saveTokens: ((data: THTokenSave, req: any) => boolean)
        | ((data: THTokenSave, req: any) => Promise<boolean>);
    /**
     * Used by the `authenticate`, `introspection`, `revocation`
     * functions to inquire if an access token is registered to the database.
     * If the access token still exists in the database you have to return it as it is,
     * otherwise `null`.
     *
     * This function also supports async calls.
     * @param data The access token alongside some other data that were used when saving the tokens.
     * @param req The request instance.
     * @return {string|null} The access token if it exists, null otherwise.
     */
    getAccessToken: ((data: THAccessTokenAsk, req: any) => PlusUN<string>)
        | ((data: THAccessTokenAsk, req: any) => Promise<PlusUN<string>>);
    /**
     * Used by the `revocation` function and `Refresh Token`
     * flow to inquire if a refresh token is registered in the database.
     * If the refresh token still exists in the database you have to return it as it is,
     * otherwise `null`.
     *
     * This function also supports async calls.
     * @param data The refresh token alongside some other data that were used when saving the tokens.
     * @param req The request instance.
     * @return {string|null} The refresh token if it exists, null otherwise.
     */
    getRefreshToken: ((data: THRefreshTokenAsk, req: any) => PlusUN<string>)
        | ((data: THRefreshTokenAsk, req: any) => Promise<PlusUN<string>>);
    /**
     * Used by the `revocation`, `authenticate`, `introspection` functions and `Refresh Token`
     * flow to ask for the revocation of a token or a record.
     * It must always return `true` unless the database did not delete the tokens or record, in that
     * case you must return `false`.
     *
     * This function also supports async calls.
     */
    revoke: ((data: RevocationAsk, req: any) => boolean)
        | ((data: RevocationAsk, req: any) => Promise<boolean>);
};