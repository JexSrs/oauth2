import {ExpressMiddleware, RevocationAsk} from "./components/types";
import {buildQuery, error, isRedirectUriExactMatch} from "./utils/utils";
import {validateUserAgent} from "./utils/useragent";
import {verifyToken} from './utils/tokenUtils'
import {Flow} from "./components/flow";
import {AuthorizationServerOptions} from "./components/authorizationServerOptions.js";
import EventEmitter from "events";
import {Events} from "./components/events";


// Will not be implemented (under discussion)
// https://datatracker.ietf.org/doc/html/rfc8705


// TODO - https://datatracker.ietf.org/doc/html/rfc9068 (Already in readme)
// TODO - OpenID Connect - https://openid.net/connect/ - https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#endpoint
// TODO - indieAuth - https://indieauth.spec.indieweb.org/
// TODO - UMA2 - https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html
// TODO - https://datatracker.ietf.org/doc/html/rfc7591
// TODO - https://datatracker.ietf.org/doc/html/rfc7592
// TODO - https://datatracker.ietf.org/doc/html/rfc9101 (Already in readme)

// TODO - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar (experimental)
// TODO - https://datatracker.ietf.org/doc/html/rfc9126 (experimental)
// TODO - https://datatracker.ietf.org/doc/html/draft-fett-oauth-dpop (experimental)
// TODO - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-incremental-authz (experimental)

// TODO - https://datatracker.ietf.org/doc/html/rfc7521
// TODO - https://datatracker.ietf.org/doc/html/rfc7523
// TODO - https://datatracker.ietf.org/doc/html/rfc7522

// TODO - https://datatracker.ietf.org/doc/html/rfc8414 - https://datatracker.ietf.org/doc/html/rfc8628#section-4

// TODO - https://oauth.net/webauthn/
// TODO - https://oauth.net/http-signatures/
// TODO - https://oauth.net/id-tokens-vs-access-tokens/

// TODO - Support Mac -> token_type https://stackoverflow.com/questions/5925954/what-are-bearer-tokens-and-token-type-in-oauth-2
//      - https://duckduckgo.com/?t=ffab&q=OAuth-HTTP-MAC&ia=web

// TODO - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05

// TODO - Device identification - https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.5
// TODO - device endpoint - https://datatracker.ietf.org/doc/html/rfc8628#section-5.1

// TODO - Add more functions such as revokeTokenForClient, revokeAllTokensForClient, revokeTokenForUser, revokeAllTokensForUser etc.
// TODO - Also add functions like generateClient(name, image_ur, etc): (id, secret), revokeClient (and obviously all its tokens) etc.

// TODO - Add option deleteAfterUse. This option if set to true, access tokens can only be used once and deleted immediately after use (when passing authenticate and/or introspection functions they will be deleted)
//      - Be careful here, when the token is used twice at the same time (maybe add a delay before asking database?).

// TODO - Add refresh token refresh count, can execute the refresh flow x times (meaning you can request new access token x times, after that you cannot).

// TODO - Add notBefore in options for jwt. It will be fixed value like accessTokenLifetime.
// TODO - Maybe add a function to determinate the lifetime & notBefore of tokens (access & refresh).
// TODO - Add endpoint function for the front-end to check all the data (for example if client_id (careful on abuse to find if client ids exists) is valid, or scopes ae valid, etc.)
// TODO - getClientCredentials add 'auto'. It will detect automatically where the creds are based on flow and endpoint.

export class AuthorizationServer {

    /**
     * Expose EventEmitter.
     */
    eventEmitter = new EventEmitter();
    private readonly options: Required<AuthorizationServerOptions>;
    private issueRefreshToken: boolean = false;
    private readonly flows: Flow[] = [];

    /**
     * Construct a new AuthorizationServer to handle your oauth2 requests.
     * In case you want different options for each oauth2 flow, it is recommended
     * to construct different classes with different options.
     * @param options
     */
    constructor(options: AuthorizationServerOptions) {
        let opts: AuthorizationServerOptions = Object.assign({}, options);

        if (opts.getToken === undefined)
            opts.getToken = (req) => req.headers['authorization']?.split(' ')?.[1];
        if (opts.setPayloadLocation === undefined)
            opts.setPayloadLocation = (req, payload) => req.payload = payload;

        if (opts.accessTokenLifetime === undefined)
            opts.accessTokenLifetime = 86400;
        if (opts.refreshTokenLifetime === undefined)
            opts.refreshTokenLifetime = 86400 * 10;

        if (opts.isTemporarilyUnavailable === undefined)
            opts.isTemporarilyUnavailable = false;
        if (opts.validateRequest === undefined)
            opts.validateRequest = (req) => validateUserAgent(req.headers['user-agent']);
        if (opts.isFlowAllowed === undefined)
            opts.isFlowAllowed = (client_id, flowName, req) => true;

        if (opts.scopeDelimiter === undefined)
            opts.scopeDelimiter = ' ';

        if (opts.getClientCredentials === 'header' || opts.getClientCredentials === undefined)
            opts.getClientCredentials = (req: any) => {
                let authHeader = req.headers['authorization'];
                let decoded = authHeader && Buffer.from(authHeader, 'base64').toString() || '';

                let [client_id, client_secret] = /^([^:]*):(.*)$/.exec(decoded) ?? [];
                return {client_id, client_secret};
            };
        else if (opts.getClientCredentials === 'body')
            opts.getClientCredentials = (req: any) => {
                let {client_id, client_secret} = req.body;
                return {client_id, client_secret};
            };
        else if (opts.getClientCredentials === 'query')
            opts.getClientCredentials = (req: any) => {
                let {client_id, client_secret} = req.query;
                return {client_id, client_secret};
            };

        if (opts.getUser === undefined)
            opts.getUser = (req) => req.user;

        if (opts.audience === undefined)
            opts.audience = opts.issuer;

        if (opts.allowAuthorizeMethodPOST === undefined)
            opts.allowAuthorizeMethodPOST = false;

        if(opts.issueRefreshTokenForThisClient === undefined)
            opts.issueRefreshTokenForThisClient = (client_id, req) => true;

        ['validateClient', 'validateRedirectURI', 'validateScopes', 'secret', 'issuer', 'saveTokens', 'getAccessToken', 'getRefreshToken']
            .forEach(field => {
                if ((opts as any)[field] === undefined) throw new Error(`AuthorizationServerException Field ${field} cannot be undefined`);
            });

        this.options = opts as Required<AuthorizationServerOptions>;
    }

    /**
     * Register a new flow.
     * @param flow You can provide more than one implementation in the same time.
     */
    public use(flow: Flow | Flow[]): AuthorizationServer {
        let flows = Array.isArray(flow) ? flow : [flow];
        flows.forEach(fl => {
            if (!fl.name) throw new Error('Flow name is missing');
            if (!['authorize', 'token', 'device_authorization'].includes(fl.endpoint))
                throw new Error(`Flow ${fl.name} has invalid endpoint`);

            if (fl.matchType.trim().length === 0)
                console.log(`Flow ${fl.name} has empty match type which is not recommended`);

            // Match type duplication check for each endpoint
            let i;
            if ((i = this.flows.find(i => i.endpoint === fl.endpoint && i.matchType === fl.matchType)) != null)
                throw new Error(`Flow ${fl.name} has the same match type as ${i.name} at the same endpoint`);

            if (typeof fl.function !== 'function')
                throw new Error(`Flow ${fl.name} has invalid function`);

            if (fl.name === 'refresh-token')
                this.issueRefreshToken = true;

            this.flows.push(fl)
        });

        return this;
    }

    /**
     * Register a new listener for an event.
     * @param event
     * @param listener
     */
    public on(event: string, listener: (...args: any[]) => void): AuthorizationServer {
        this.eventEmitter.on(event, listener);
        return this;
    }

    /**
     * The `authorize` function.
     *
     * The authorization endpoint is not the responsible for the user authentication,
     * so do not forget to authenticate the user before reaching this function.
     */
    public authorize(overrideOptions?: Partial<AuthorizationServerOptions>): ExpressMiddleware {
        const options = Object.assign({}, this.options, overrideOptions || {});

        return async (req, res, next) => {
            let dataFrom;
            if (req.method === 'GET') {
                dataFrom = req.query;
            } else if (req.method === 'POST' && options.allowAuthorizeMethodPOST) {
                dataFrom = req.body;
            } else {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {client_id, redirect_uri, state, scope, response_type} = dataFrom;

            if (!client_id)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Query parameter client_id is missing',
                });

            if (!redirect_uri)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Query parameter redirect_uri is missing'
                });

            if (!response_type)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Query parameter response_type is missing'
                });

            // Validate client_id and redirect_uri
            const redirectUri: any = await options.validateRedirectURI(client_id, redirect_uri, req);
            // If redirect uri is not false then it can be true or a redirect uri.
            if (redirectUri === false || (redirectUri !== true && !isRedirectUriExactMatch(redirectUri, redirect_uri))) {
                this.eventEmitter.emit(Events.INVALID_REDIRECT_URI, req);
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Redirect URI is not registered',
                    error_uri: options.errorUri,
                });
            }


            // Server is temporary unavailable
            if ((typeof options.isTemporarilyUnavailable === 'boolean' || typeof options.isTemporarilyUnavailable === 'undefined'
                ? options.isTemporarilyUnavailable
                : await options.isTemporarilyUnavailable(req)))
                return error(res, {
                    error: 'temporarily_unavailable',
                    error_description: 'The authorization server is temporary unavailable',
                    error_uri: options.errorUri,
                    redirect_uri,
                    state
                });

            // Embedded WebViews, bots, etc.
            if (!(await options.validateRequest(req))) {
                this.eventEmitter.emit(Events.INVALID_REQUEST, req);
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'The request was made from a not acceptable source',
                    error_uri: options.errorUri,
                    redirect_uri,
                    state
                });
            }

            // Validate scopes
            let scopes: string[] = scope?.split(options.scopeDelimiter) || [];
            const scopeResult = await options.validateScopes(scopes, req);
            if(Array.isArray(scopeResult))
                scopes = scopeResult;
            else if (scopeResult === false) {
                this.eventEmitter.emit(Events.INVALID_SCOPES, req);
                return error(res, {
                    error: 'invalid_scope',
                    error_description: 'One or more scopes are not acceptable',
                    error_uri: options.errorUri,
                    redirect_uri,
                    state
                });
            }

            // Get user identification
            let user = options.getUser(req);
            if (user == null) {
                this.eventEmitter.emit(Events.ACCESS_DENIED, req);
                return error(res, {
                    error: 'access_denied',
                    error_description: 'User did not authorize client',
                    error_uri: options.errorUri,
                    redirect_uri,
                    state
                });
            }

            // TODO - to support openid, first split response_type with space and then check
            //      - id token will be generated here and be included in the response from here.

            // Find flow
            let flow = this.flows.find(imp => imp.endpoint === 'authorize' && imp.matchType === response_type);
            if (!flow) {
                this.eventEmitter.emit(Events.UNSUPPORTED_RESPONSE_TYPE, req);
                return error(res, {
                    error: 'unsupported_response_type',
                    error_description: `Response type ${response_type} is not supported`,
                    error_uri: options.errorUri,
                    redirect_uri,
                    state
                });
            }

            if (!(await options.isFlowAllowed(client_id, flow.name, req))) {
                this.eventEmitter.emit(Events.REJECTED_FLOW, req);
                return error(res, {
                    error: 'unauthorized_client',
                    error_description: 'This client does not have access to use this flow',
                    error_uri: options.errorUri,
                    redirect_uri,
                    state
                });
            }

            // Issue refresh token
            let issueRefreshToken = this.issueRefreshToken;
            if(issueRefreshToken)
                issueRefreshToken = await options.issueRefreshTokenForThisClient(client_id, req);

            // Call implementation function
            flow.function({
                req,
                serverOpts: options,
                scopes, user,
                issueRefreshToken,
                clientId: client_id
            }, (response, err) => {
                if (err)
                    return error(res, {
                        error: err.error,
                        error_description: err.error_description,
                        error_uri: err.error_uri ?? options.errorUri,
                        redirect_uri,
                        state
                    });

                const url = `${redirect_uri}?${buildQuery({...response, state})}`;
                res.header('Cache-Control', 'no-store').status(302).redirect(url);
            }, this.eventEmitter);
        };
    }

    /**
     * The `token` function.
     */
    public token(overrideOptions?: Partial<AuthorizationServerOptions>): ExpressMiddleware {
        const options = Object.assign({}, this.options, overrideOptions || {});
        return this.clientEndpoint(options, 'token');
    }

    /**
     * The `device` function.
     */
    public deviceAuthorization(overrideOptions?: Partial<AuthorizationServerOptions>): ExpressMiddleware {
        const options = Object.assign({}, this.options, overrideOptions || {});
        return this.clientEndpoint(options, 'device_authorization');
    }

    /**
     * The `introspection` function.
     */
    public introspection(overrideOptions?: Partial<AuthorizationServerOptions>): ExpressMiddleware {
        const options = Object.assign({}, this.options, overrideOptions || {});

        const inactive = (res: any): void => {
            res.status(200).json({active: false});
        }

        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            let {client_id, client_secret} = (options.getClientCredentials as any)(req);
            if (!(await options.validateClient(client_id, client_secret, req))) {
                return error(res, {
                    error: 'unauthorized_client',
                    error_description: 'Client authentication failed',
                    error_uri: options.errorUri
                });
            }

            const {token, token_type_hint} = req.body;
            if (!token) return inactive(res);

            let payload: any = verifyToken(token, options.secret, undefined, options.issuer);
            if (!payload) return inactive(res);

            if (payload.type !== 'access_token')
                return inactive(res);

            let dbToken = await options.getAccessToken({
                accessToken: token,
                clientId: payload.client_id,
                user: payload.user
            }, req);

            if (!dbToken || dbToken !== token)
                return inactive(res);

            res.status(200).json({
                active: true,
                scope: payload.scopes.join(options.scopeDelimiter),
                client_id: payload.client_id,
                user: payload.user,
                token_type: 'Bearer',
                exp: payload.exp,
                iat: payload.iat,
                sub: payload.sub,
                aud: payload.aud,
                iss: payload.iss,
                jti: payload.jti
            });
        }
    }

    /**
     * The `revocation` function.
     */
    public revocation(overrideOptions?: Partial<AuthorizationServerOptions>): ExpressMiddleware {
        const options = Object.assign({}, this.options, overrideOptions || {});

        // For invalid tokens error response is not required
        // As documented at https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            let {client_id, client_secret} = (options.getClientCredentials as any)(req);
            if (!(await options.validateClient(client_id, client_secret, req))) {
                return error(res, {
                    error: 'unauthorized_client',
                    error_description: 'Client authentication failed',
                    error_uri: options.errorUri
                });
            }

            let {token, token_type_hint} = req.body;

            // Verify if the token sent was issued by us.
            // Audience is not needed, because we revoke a token that we have issued.
            let payload: any = verifyToken(token, options.secret, undefined, options.issuer);
            if (!payload) return res.status(200).end(null);

            // Verify token payload
            if (payload.client_id !== client_id) // TODO - Maybe return an error here
                return res.status(200).end(null);

            // Get token from database
            let dbToken = payload.type === 'access_token'
                ? await options.getAccessToken({
                    accessToken: token,
                    clientId: payload.client_id,
                    user: payload.user
                }, req)
                : await options.getRefreshToken({
                    refreshToken: token,
                    clientId: payload.client_id,
                    user: payload.user
                }, req);

            // Token does not exist in db, si it was revoked in the past.
            if (!dbToken || token !== dbToken)
                return res.status(200).end(null);

            // Revoke token
            const dbRes = await options.revoke({
                what: payload.type,
                clientId: payload.client_id,
                user: payload.user,
                [payload.type === 'access_token' ? 'accessToken' : 'refreshToken']: token
            } as RevocationAsk, req);

            if (!dbRes) {
                // If the server responds with HTTP status code 503, the client must
                // assume the token still exists and may retry after a reasonable delay.
                res.status(503)
                    .header('Retry-After', `${60}`) // TODO - Add as option here
                    .end(null);
                return
            }

            return res.status(200).end(null);
        }
    }

    /**
     * The `authenticate` function.
     *
     * Used by small projects when authorization and resource server are hosted by the same application.
     *
     * @param scope The scopes needed for this request. If the access token scopes are insufficient
     *              then the authentication will fail. If scope is not initialized then the scope
     *              check will be omitted. If there are multiple scopes use an array.
     * @param cond If more than one scopes are provided, whether the access token must have all the scopes
     *              or at least one of them. Defaults to `all`.
     * @param overrideOptions
     */
    public authenticate(scope?: string[] | string, cond?: 'all' | 'some', overrideOptions?: Partial<AuthorizationServerOptions>): ExpressMiddleware {
        const options = Object.assign({}, this.options, overrideOptions || {});

        let scopes: string[] | undefined = Array.isArray(scope) ? scope : (scope ? [scope] : undefined);
        let condition = cond || 'all';

        return async (req, res, next) => {
            let token = options.getToken(req);
            if (!token) {
                this.eventEmitter.emit(Events.AUTHENTICATION_MISSING_TOKEN, req);
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'No access token was provided',
                    error_uri: options.errorUri,
                    noCache: false
                });
            }

            let payload: any = verifyToken(token, options.secret, options.issuer, options.issuer);
            if (!payload) {
                this.eventEmitter.emit(Events.AUTHENTICATION_INVALID_TOKEN_JWT, req);
                return error(res, {
                    error: 'invalid_token',
                    error_description: 'The access token has expired',
                    error_uri: options.errorUri,
                    status: 401,
                    noCache: false
                });
            }

            if (payload.type !== 'access_token') {
                this.eventEmitter.emit(Events.AUTHENTICATION_INVALID_TOKEN_NOT, req);
                return error(res, {
                    error: 'invalid_token',
                    error_description: 'The token is not an access token',
                    error_uri: options.errorUri,
                    status: 401,
                    noCache: false
                });
            }

            let dbToken = await options.getAccessToken({
                accessToken: token,
                clientId: payload.client_id,
                user: payload.user
            }, req);

            if (!dbToken || dbToken !== token) {
                this.eventEmitter.emit(Events.AUTHENTICATION_INVALID_TOKEN_DB, req);
                return error(res, {
                    error: 'invalid_token',
                    error_description: 'The access token has expired',
                    error_uri: options.errorUri,
                    status: 401,
                    noCache: false
                });
            }

            if (scopes) {
                if (
                    (condition === 'all' && scopes.some((v: string) => !payload.scopes!.includes(v)))
                    || (condition === 'some' && payload.scopes.some((v: string) => !scopes!.includes(v)))
                ) {
                    this.eventEmitter.emit(Events.AUTHENTICATION_INVALID_TOKEN_SCOPES, req);
                    return error(res, {
                        error: 'insufficient_scope',
                        error_description: 'Client does not have access to this endpoint',
                        error_uri: options.errorUri,
                        status: 403,
                        noCache: false
                    });
                }
            }

            options.setPayloadLocation(req, {
                clientId: payload.client_id,
                user: payload.user,
                scopes: payload.scopes,
                aud: payload.aud,
                iss: payload.iss,
                jti: payload.jti,
                iat: payload.iat
            });
            next();
        };
    }

    private clientEndpoint(options: Required<AuthorizationServerOptions>, endpoint: string): ExpressMiddleware {
        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {grant_type} = req.body;
            let {client_id, client_secret} = (options.getClientCredentials as any)(req);

            if (!grant_type)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Body parameter grant_type is missing'
                });

            if (!client_id)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Body parameter client_id is missing',
                    error_uri: options.errorUri
                });

            if (!(await options.validateClient(client_id, client_secret, req))) {
                return error(res, {
                    error: 'unauthorized_client',
                    error_description: 'Client authentication failed',
                    error_uri: options.errorUri
                });
            }

            let flow = this.flows.find(imp => imp.endpoint === endpoint && imp.matchType === grant_type);
            if (!flow) {
                this.eventEmitter.emit(Events.UNSUPPORTED_GRANT_TYPE, req);
                return error(res, {
                    error: 'unsupported_grant_type',
                    error_description: `Grant type ${grant_type} is not supported`,
                    error_uri: options.errorUri
                });
            }

            if (!(await options.isFlowAllowed(client_id, flow.name, req))) {
                this.eventEmitter.emit(Events.REJECTED_FLOW, req);
                return error(res, {
                    error: 'unauthorized_client',
                    error_description: 'This client does not have access to use this flow',
                    error_uri: options.errorUri
                });
            }

            // Issue refresh token
            let issueRefreshToken = this.issueRefreshToken;
            if(issueRefreshToken)
                issueRefreshToken = await options.issueRefreshTokenForThisClient(client_id, req);

            flow.function({
                req,
                serverOpts: options,
                issueRefreshToken,
                clientId: client_id
            }, (response, err) => {
                if (err)
                    return error(res, {
                        error: err.error,
                        error_description: err.error_description,
                        error_uri: err.error_uri ?? options.errorUri,
                        status: err.status
                    });

                res.header('Cache-Control', 'no-store').status(200).json(response);
            }, this.eventEmitter);
        };
    }
}
