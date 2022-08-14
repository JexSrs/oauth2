import {ARTokens, ExpressMiddleware, RevocationAsk} from "./components/types";
import {buildQuery, error, isRedirectUriExactMatch, passToNext, resolveUrl} from "./utils/utils";
import {validateUserAgent} from "./utils/useragent";
import {signToken, verifyToken} from './utils/tokenUtils'
import {Flow} from "./components/flow";
import {AuthorizationServerOptions} from "./components/authorizationServerOptions.js";
import EventEmitter from "events";
import {Events} from "./components/events";
import {Metadata} from "./components/metadataTypes.js";
import {Interceptor} from "./components/interceptor.js";
import {decode} from "jsonwebtoken";


// Will not be implemented (under discussion)
// https://datatracker.ietf.org/doc/html/rfc8705
// https://datatracker.ietf.org/doc/html/rfc9101
// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar (experimental)
// https://datatracker.ietf.org/doc/html/draft-fett-oauth-dpop (experimental)
// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-incremental-authz (experimental)

// TODO - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05

// TODO - https://datatracker.ietf.org/doc/html/rfc7521
// TODO - https://datatracker.ietf.org/doc/html/rfc7523
// TODO - https://datatracker.ietf.org/doc/html/rfc7522

// TODO - https://datatracker.ietf.org/doc/html/rfc9126 (experimental)

// TODO - OpenID Connect - https://openid.net/connect/ - https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#endpoint
// TODO - indieAuth - https://indieauth.spec.indieweb.org/
// TODO - UMA2 - https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html

// TODO - https://datatracker.ietf.org/doc/html/rfc7591
// TODO - https://datatracker.ietf.org/doc/html/rfc7592

// TODO - Support Mac -> token_type https://stackoverflow.com/questions/5925954/what-are-bearer-tokens-and-token-type-in-oauth-2
//      - https://duckduckgo.com/?t=ffab&q=OAuth-HTTP-MAC&ia=web

// TODO - Device identification - https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.5
// TODO - device endpoint - https://datatracker.ietf.org/doc/html/rfc8628#section-5.1

// TODO - Add access/refresh token refresh count, can execute the refresh flow x times (meaning you can request new access token x times, after that you cannot).
//      - This can replace the deleteAfterUse by setting the access token count at `1`.

// TODO - Add notBefore in options for jwt. It will be fixed value like accessTokenLifetime.
// TODO - Maybe add a function to determinate the lifetime & notBefore of tokens (access & refresh).

// TODO - Add jwt subject as JSON.stringify(user)

// TODO - Find a way for flows to call interceptors, but be careful not the interceptor to be called twice.
//      - this will be useful not writing openIdConnect code twice, once for response_type=id_token and once
//      - when the token is generated at the authorization_code flow

export class AuthorizationServer {

    /**
     * Expose EventEmitter.
     */
    eventEmitter = new EventEmitter();
    private readonly options: Required<AuthorizationServerOptions>;
    private issueRefreshToken: boolean = false;
    private readonly flows: Flow[] = [];
    private readonly interceptors: Interceptor[] = [];

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
            opts.audience = opts.baseUrl;

        if (opts.deleteAfterUse === undefined)
            opts.deleteAfterUse = false

        if (opts.allowAuthorizeMethodPOST === undefined)
            opts.allowAuthorizeMethodPOST = false;

        if (opts.issueRefreshTokenForThisClient === undefined)
            opts.issueRefreshTokenForThisClient = (client_id, req) => true;

        ['validateClient', 'validateRedirectURI', 'validateScopes', 'secret', 'baseUrl', 'saveTokens', 'getAccessToken', 'getRefreshToken']
            .forEach(field => {
                if ((opts as any)[field] === undefined) throw new Error(`AuthorizationServerException Field ${field} cannot be undefined`);
            });

        this.options = opts as Required<AuthorizationServerOptions>;
    }

    /**
     * Register a new flow.
     * @param flow
     */
    public use(flow: Flow | Flow[]): this {
        let flows = Array.isArray(flow) ? flow : [flow];
        flows.forEach(fl => {
            if (!fl.name) throw new Error('Flow name is missing');
            if (!['authorize', 'token', 'device_authorization'].includes(fl.endpoint))
                throw new Error(`Flow ${fl.name} has invalid endpoint`);

            if (fl.matchType.trim().length === 0)
                throw new Error(`Flow ${fl.name} has empty match type which is not allowed`);

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
     * Register a new interceptor.
     * @param interceptor
     */
    public intercept(interceptor: Interceptor | Interceptor[]): this {
        let inters = Array.isArray(interceptor) ? interceptor : [interceptor];
        inters.forEach(it => {
            if (!it.name) throw new Error('Interceptor name is missing');
            if (!['authorize', 'token', 'device_authorization'].includes(it.endpoint))
                throw new Error(`Interceptor ${it.name} has invalid endpoint`);

            if (!(it as any).matchType && !(it as any).matchScope)
                throw new Error(`Interceptor ${it.name} has empty matchType and matchScope which is not allowed`);

            // ... Interceptors can share the same matchTypes

            if (typeof it.function !== 'function')
                throw new Error(`Interceptor ${it.name} has invalid function`);

            this.interceptors.push(it)
        });

        return this;
    }

    /**
     * Register a new listener for an event.
     * @param event
     * @param listener
     */
    public on(event: string, listener: (...args: any[]) => void): this {
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
                    error_description: 'Parameter client_id is missing',
                });

            if (!redirect_uri)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Parameter redirect_uri is missing'
                });

            if (!response_type)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Parameter response_type is missing'
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
            if (Array.isArray(scopeResult))
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

            const rTypes = response_type.split(' ');

            // Find flow
            const flow = this.flows.find(imp => imp.endpoint === 'authorize' && rTypes.includes(imp.matchType));
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
            if (issueRefreshToken)
                issueRefreshToken = await options.issueRefreshTokenForThisClient(client_id, req);

            // Find interceptor
            const typeInterceptors = this.interceptors.filter(it => it.endpoint === 'authorize' && rTypes.includes(it.matchType));

            // Call implementation function
            const responseOrError = await flow.function({
                req,
                serverOpts: options,
                scopes, user,
                issueRefreshToken,
                clientId: client_id
            }, this.eventEmitter);

            if ((responseOrError as any).error)
                return error(res, {
                    error: (<any>responseOrError).error,
                    error_description: (<any>responseOrError).error_description,
                    error_uri: (<any>responseOrError).error_uri ?? options.errorUri,
                    redirect_uri,
                    state
                });

            let response: {[key: string]: string | number} = <any>responseOrError;

            // Call interceptors
            response = await passToNext(typeInterceptors,
                response ?? {},
                (p, v) => p.function({
                    req,
                    serverOpts: options,
                    response: v,
                    clientId: client_id
                }, this.eventEmitter) as any
            );

            const url = `${redirect_uri}?${buildQuery({...response, state})}`;
            res.header('Cache-Control', 'no-store').status(302).redirect(url);
        };
    }

    /**
     * The `token` function.
     */
    public token(overrideOptions?: Partial<AuthorizationServerOptions>): ExpressMiddleware {
        const options = Object.assign({}, this.options, overrideOptions || {});
        return this.postEndpoint(options, 'token');
    }

    /**
     * The `device` function.
     */
    public deviceAuthorization(overrideOptions?: Partial<AuthorizationServerOptions>): ExpressMiddleware {
        const options = Object.assign({}, this.options, overrideOptions || {});
        return this.postEndpoint(options, 'device_authorization');
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

            let payload: any = verifyToken(token, options.secret, undefined, options.baseUrl);
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

            // Delete token if deleteAfterUse is `true`
            if (options.deleteAfterUse) {
                const deleted = await options.revoke({
                    what: 'access_token',
                    user: payload.user,
                    clientId: payload.client_id,
                    accessToken: token
                }, req)

                if (!deleted)
                    return inactive(res);
            }

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
            let payload: any = verifyToken(token, options.secret, undefined, options.baseUrl);
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

            let payload: any = verifyToken(token, options.secret, options.baseUrl, options.baseUrl);
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

            // Request token
            let dbToken = await options.getAccessToken({
                accessToken: token,
                clientId: payload.client_id,
                user: payload.user
            }, req);

            // Validate token from db
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

            // Delete token if deleteAfterUse is `true`
            if (options.deleteAfterUse) {
                const deleted = await options.revoke({
                    what: 'access_token',
                    user: payload.user,
                    clientId: payload.client_id,
                    accessToken: token
                }, req)

                if (!deleted) {
                    this.eventEmitter.emit(Events.AUTHENTICATION_INVALID_TOKEN_DB, req);
                    return error(res, {
                        error: 'invalid_token',
                        error_description: 'The access token has expired',
                        error_uri: options.errorUri,
                        status: 401,
                        noCache: false
                    });
                }
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

    /**
     * The metadata function.
     */
    public metadata(): ExpressMiddleware {
        const data = this.options.metadata;
        if (!data) throw new Error('AuthorizationServerException metadata was notdefined in options.')

        const authorizationTypes = this.flows.filter(flow => flow.endpoint === 'authorize').map(flow => flow.matchType);
        const tokenTypes = this.flows.filter(flow => flow.endpoint === 'token').map(flow => flow.matchType);

        if (authorizationTypes.length > 0 && !data.authorizationPath)
            throw new Error('AuthorizationServerException Authorization endpoint is missing');

        if (tokenTypes.length > 0 && !data.tokenPath)
            throw new Error('AuthorizationServerException Token endpoint is missing');

        let metadata: Partial<Metadata> = {
            // Flows
            response_types_supported: authorizationTypes,
            grant_types_supported: tokenTypes.length > 0 ? tokenTypes : ['authorization_code', 'implicit'],

            // Endpoints
            authorization_endpoint: resolveUrl(this.options.baseUrl, data.authorizationPath!),
            token_endpoint: resolveUrl(this.options.baseUrl, data.tokenPath!),
            registration_endpoint: data.registrationPath ? resolveUrl(this.options.baseUrl, data.registrationPath) : undefined,
            revocation_endpoint: data.revocationPath ? resolveUrl(this.options.baseUrl, data.revocationPath) : undefined,
            introspection_endpoint: data.introspectionPath ? resolveUrl(this.options.baseUrl, data.introspectionPath) : undefined,
            device_authorization_endpoint: data.deviceAuthorizationPath ? resolveUrl(this.options.baseUrl, data.deviceAuthorizationPath) : undefined,

            // Other
            issuer: this.options.baseUrl,
            ui_locales_supported: data.ui_locales_supported,

            jwks_uri: data.jwksUri,
            scopes_supported: data.scopes_supported ?? [],
            response_modes_supported: data.response_modes_supported ?? ['query', 'fragment'],
            token_endpoint_auth_methods_supported: data.token_endpoint_auth_methods_supported ?? ['client_secret_basic'],
            token_endpoint_auth_signing_alg_values_supported: data.token_endpoint_auth_signing_alg_values_supported,
            service_documentation: data.serviceDocumentation,
            op_policy_uri: data.op_policy_uri,
            op_tos_uri: data.op_tos_uri,
            revocation_endpoint_auth_methods_supported: data.revocation_endpoint_auth_methods_supported ?? ['client_secret_basic'],
            revocation_endpoint_auth_signing_alg_values_supported: data.revocation_endpoint_auth_signing_alg_values_supported,
            introspection_endpoint_auth_signing_alg_values_supported: data.introspection_endpoint_auth_signing_alg_values_supported,
            introspection_endpoint_auth_methods_supported: data.introspection_endpoint_auth_methods_supported,
            code_challenge_methods_supported: data.code_challenge_methods_supported,
        };

        metadata.signed_metadata = signToken({
            payload: {
                ...metadata,
                issuer: undefined
            },
            secret: this.options.secret,
            issuer: this.options.baseUrl,
            audience: undefined
        });

        return (req, res, next) => res.status(200).json(metadata);
    }

    private postEndpoint(options: Required<AuthorizationServerOptions>, endpoint: string): ExpressMiddleware {
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

            const gTypes = grant_type.split(' ');

            let flow = this.flows.find(imp => imp.endpoint === endpoint && gTypes.includes(imp.matchType));
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
            if (issueRefreshToken)
                issueRefreshToken = await options.issueRefreshTokenForThisClient(client_id, req);

            // Filter interceptors (by endpoint)
            const scopeInterceptors = this.interceptors.filter(it => it.endpoint === endpoint);

            const responseOrError = await flow.function({
                req,
                serverOpts: options,
                issueRefreshToken,
                clientId: client_id
            }, this.eventEmitter);

            if ((responseOrError as any).error)
                return error(res, {
                    error: (<any>responseOrError).error,
                    error_description: (<any>responseOrError).error_description,
                    error_uri: (<any>responseOrError).error_uri ?? options.errorUri,
                    status: (<any>responseOrError).status
                });

            let response: {[key: string]: string | number} = <any>responseOrError;

            // Filter interceptor by scope here (because only here we know the scope)
            const scopes = (response as ARTokens).scope?.split(options.scopeDelimiter) ?? [];

            // Call interceptors
            response = await passToNext(scopeInterceptors.filter(it => scopes.includes((it as any).matchScope)),
                response ?? {},
                (p, v) => p.function({
                    req,
                    serverOpts: options,
                    response: v,
                    clientId: client_id
                }, this.eventEmitter) as any
            );

            res.header('Cache-Control', 'no-store').status(200).json(response);
        };
    }
}
