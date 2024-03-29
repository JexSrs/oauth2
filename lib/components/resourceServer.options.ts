export type ResourceServerOptions = {
    /**
     * Used by the `authenticate` function of the `ResourceServer` to inquire about the
     * location of the access token. It defaults to the authorization header.
     * @param req The request instance.
     * @return {string|null} The token that the client passed or null if no token found.
     */
    getToken?: (req: any) => string;
    /**
     * Used by the `authenticate` function of the `ResourceServer` to inquire about the
     * where to save the `payload` if the authentication succeeds. It defaults to `req.payload`.
     * @param req The request instance.
     * @param payload The payload that will be saved at the request instance.
     */
    setPayloadLocation?: (req: any, payload: object) => void;
    /**
     * Used by the `authenticate` function of the `ResoureServer` to inquire extra any headers
     * that will be sent to the `introspection` endpoint.
     *
     * It defaults to `{'Content-Type': 'application/x-www-form-urlencoded'}`.
     */
    headers?: { [key: string]: string | string[] };
    /**
     * Used by the `authenticate` function of the `ResoureServer` to inquire if a body will
     * be sent alongside the `token` to the `introspection` endpoint.
     *
     * For example if the authentication must be done from the body instead of the headers
     * you can include your credentials here.
     */
    body?: { [key: string]: string | string[] };
    /**
     * Used by the `authenticate` function of the `ResoureServer` to inquire the location
     * of the `introspection` endpoint. If not set it will validate the client using JWT
     * verification without asking the authorization server.
     */
    introspectionURL?: string;
    /**
     * The delimiter that will be used to split the scope string.
     * It defaults to one space character (`' '`).
     */
    scopeDelimiter?: string;
    /**
     * The server can also return a URL to a human-readable web page with information about the error.
     * This is intended for the developer to get more information about the error, and is not meant
     * to be displayed to the end user.
     */
    errorUri?: string;
    /**
     * The resource server's `audience`. It will be used to inquire if the token send to the
     * `AuthorizationServer` through the `introspection` endpoint is meant to be used to
     * the current `ResourceServer`.
     */
    audience: string;
    /**
     * The `AuthorizationServer` uses JsonWebToken (JWT) for generating any kind of tokens.
     *
     * If you do not want to use the introspection endpoint for validating if
     * an access token is valid, you can assign the same secret with the authorization server.
     *
     * By using this feature you will have a less request to the authorization server for every
     * request (that needs authentication) in the resource server. On the other hand you will
     * not be able to revoke an access token until it has expired on its own.
     */
    secret: string;
    /**
     * If you use the `secret` option above you also have to define the `issuer` option
     * with the same value as the authorization server `issuer` option.
     */
    issuer: string;
};