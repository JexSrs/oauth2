export type ResourceServerOptions = {
    /**
     * The authorization server url, where the resource servers ask
     * to verify if a token is valid.
     */
    introspectionURL: string;
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
     * Extra headers that ou may want to send to the authorization server when authenticating a request.
     * For example, if the introspection endpoint is public, and you want to protect it with client credentials
     * then adding the credentials to the header may do the job done!
     */
    introspectionHeaders?: {[key: string]: string | string[]};
    /**
     * The delimiter that will be used to split the scope string.
     * This has to match the authorization server scopeDelimiter.
     * Defaults to ' ' (one space character).
     */
    scopeDelimiter?: string;
    /**
     * The error uri that will be passed with the response in case of error.
     */
    errorUri?: string;
};