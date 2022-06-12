export type ResourceServerOptions = {
    /**
     * The authorization server's introspection url.
     * This is the url where the resource servers ask to verify if a token is valid.
     */
    introspectionURL: string;
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
     * Extra headers that you may want to send to the authorization server when authenticating a request.
     * For example, if the introspection endpoint is public, and you want to protect it with client credentials
     * then adding the credentials to the header may do the job done!
     */
    introspectionHeaders?: {[key: string]: string | string[]};
    /**
     * The delimiter that will be used to split the scope string.
     * Defaults to ' ' (one space character).
     */
    scopeDelimiter?: string;
    /**
     * The error uri that will be passed with the error response.
     */
    errorUri?: string;
};