import {ExpressMiddleware} from "./components/types";
import {buildQuery, error, validateUserAgent} from "./modules/utils";
import {verifyToken} from './modules/tokenUtils'
import {Implementation} from "./components/implementation";
import {AuthorizationServerOptions} from "./components/options/authorizationServerOptions";
import EventEmitter from "events";
import {Events} from "./components/events";

// TODO - Support Mac -> token_type https://stackoverflow.com/questions/5925954/what-are-bearer-tokens-and-token-type-in-oauth-2
// TODO - Support to do all checks async using Promise.all([p1, p2, p3]).spread(function (r1, r2, r3) {})
// TODO - Support openid https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#endpoint
// TODO - Add more functions such as expireTokenForClient, expireAllTokensForClient, expire tokenForUser, expireAllTokensForUser etc.

export class AuthorizationServer {

    private readonly options: Required<AuthorizationServerOptions>;
    private issueRefreshToken: boolean = false;

    private readonly implementations: Implementation[] = [];
    private readonly eventEmitter = new EventEmitter();

    /**
     * Construct a new AuthorizationServer to handle your oauth2 requests.
     * In case you want different options for each oauth2 flow, it is recommended
     * to construct different classes with different options.
     * @param options
     */
    constructor(options: AuthorizationServerOptions) {
        let opts: AuthorizationServerOptions = {...options};

        if (!opts.getToken)
            opts.getToken = (req) => req.headers['authorization']?.split(' ')?.[1];

        if (!opts.setPayloadLocation)
            opts.setPayloadLocation = (req, payload) => req.payload = payload;

        if (typeof opts.accessTokenLifetime === 'undefined')
            opts.accessTokenLifetime = 86400;
        else if (opts.accessTokenLifetime != null) {
            if (opts.accessTokenLifetime <= 0 || Math.trunc(opts.accessTokenLifetime) !== opts.accessTokenLifetime)
                throw new Error('accessTokenLifetime is not positive integer.')
        }

        if (typeof opts.refreshTokenLifetime === 'undefined')
            opts.refreshTokenLifetime = 86400 * 10;
        else if (opts.refreshTokenLifetime != null) {
            if (opts.refreshTokenLifetime <= 0 || Math.trunc(opts.refreshTokenLifetime) !== opts.refreshTokenLifetime)
                throw new Error('refreshTokenLifetime is not positive integer.')
        }

        if (typeof opts.isTemporaryUnavailable === 'undefined')
            opts.isTemporaryUnavailable = false;

        if (typeof opts.validateUserAgent === 'undefined')
            opts.validateUserAgent = validateUserAgent;

        if (typeof opts.isGrantTypeAllowed === 'undefined')
            opts.isGrantTypeAllowed = (client_id) => true;

        if (typeof opts.scopeDelimiter === 'undefined')
            opts.scopeDelimiter = ' ';

        if(opts.getClientCredentials === 'header' || opts.getClientCredentials === undefined)
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

        this.options = opts as Required<AuthorizationServerOptions>;
    }

    /**
     * Register a new implementation.
     * @param implementation
     */
    public use(implementation: Implementation | Implementation[]): AuthorizationServer {
        let imps = Array.isArray(implementation) ? implementation : [implementation];
        imps.forEach(imp => {
            // Name check
            if (!imp.name)
                throw new Error('Implementation name is missing');

            // Endpoint check
            if (imp.endpoint !== 'token' && imp.endpoint !== 'authorize')
                throw new Error(`Implementation ${imp.name} has invalid endpoint`);

            // Response or grant type check
            if (typeof imp.matchType !== 'string')
                throw new Error('Implementation match type is not valid');
            if (imp.matchType.trim().length === 0)
                console.log(`Implementation ${imp.name} has empty match type which is not recommended`);

            // Match type duplication check for each endpoint
            let i;
            if ((i = this.implementations.find(i => i.endpoint === imp.endpoint && i.matchType === imp.matchType)) != null)
                throw new Error(`Implementation ${imp.name} (${imp.matchType}) has the same match type as ${i.name} (${imp.matchType})`);

            if (typeof imp.function !== 'function')
                throw new Error(`Implementation ${imp.name} has invalid function`);

            if (imp.name === 'refresh-token')
                this.issueRefreshToken = true;

            this.implementations.push(imp)
        });

        return this;
    }

    /**
     * By using the eventEmitter of Node.JS, events will be emitted.
     * Each event will be accompanied by the request instance of the server.
     * Careful, because this might expose confidential data, such as the client_id or client_secret.
     * @param event
     * @param listener
     */
    public on(event: string, listener: (...args: any[]) => void) {
        this.eventEmitter.on(event, listener);
    }

    /**
     * Assign this function to the 'authorize' endpoint with GET method.
     * Recommended endpoint: GET /api/oauth/v2/authorize
     */
    public authorize(): ExpressMiddleware {
        return async (req, res, next) => {
            if (req.method !== 'GET') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {client_id, redirect_uri, state, scope, response_type} = req.query;

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
            if (!(await this.options.validateRedirectURI(client_id, redirect_uri))) {
                this.eventEmitter.emit(Events.AUTHORIZATION_REDIRECT_URI_INVALID, req);
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Redirect URI is not registered',
                    error_uri: this.options.errorUri,
                });
            }

            // Server is temporary unavailable
            if ((typeof this.options.isTemporaryUnavailable === 'boolean' || typeof this.options.isTemporaryUnavailable === 'undefined'
                ? this.options.isTemporaryUnavailable
                : await this.options.isTemporaryUnavailable(req)))
                return error(res, {
                    error: 'temporary_unavailable',
                    error_description: 'The authorization server is temporary unavailable',
                    error_uri: this.options.errorUri,
                    redirect_uri,
                    state
                });

            // Reject embedded web views
            if(!(await this.options.validateUserAgent(req.headers['user-agent']))) {
                this.eventEmitter.emit(Events.AUTHORIZATION_USERGAENT_INVALID, req);
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'The request was made from a not acceptable source',
                    error_uri: this.options.errorUri,
                    redirect_uri,
                    state
                });
            }

            // Get user identification
            let user: any;
            if ((user = this.options.getUser(req)) == null)
                return error(res, {
                    error: 'access_denied',
                    error_description: 'User did not authorize client',
                    error_uri: this.options.errorUri,
                    redirect_uri,
                    state
                });

            let imp = this.implementations.find(imp => imp.endpoint === 'authorize' && imp.matchType === response_type);
            if (!imp) {
                this.eventEmitter.emit(Events.AUTHORIZATION_RESPONSE_TYPE_UNSUPPORTED, req);
                return error(res, {
                    error: 'unsupported_response_type',
                    error_description: `Response type ${response_type} is not supported`,
                    error_uri: this.options.errorUri,
                    redirect_uri,
                    state
                });
            }

            if (!(await this.options.isGrantTypeAllowed!(client_id, imp.name))) {
                this.eventEmitter.emit(Events.AUTHORIZATION_RESPONSE_TYPE_REJECT, req);
                return error(res, {
                    error: 'unauthorized_client',
                    error_description: 'This client does not have access to use this authorization flow',
                    error_uri: this.options.errorUri,
                    redirect_uri,
                    state
                });
            }

            // Validate scopes
            let scopes: string[] = scope?.split(this.options.scopeDelimiter) || [];
            if (!(await this.options.isScopesValid(scopes))) {
                this.eventEmitter.emit(Events.AUTHORIZATION_SCOPES_INVALID, req);
                return error(res, {
                    error: 'invalid_scope',
                    error_description: 'One or more scopes are not acceptable',
                    error_uri: this.options.errorUri,
                    redirect_uri,
                    state
                });
            }

            // Call implementation function
            imp.function(req, {...this.options}, this.issueRefreshToken, (response, err) => {
                if (err)
                    return error(res, {
                        error: err.error,
                        error_description: err.error_description,
                        error_uri: err.error_uri || this.options.errorUri,
                        redirect_uri,
                        state
                    });

                const url = `${redirect_uri}?${buildQuery({...response, state})}`;
                res.header('Cache-Control', 'no-store').redirect(url);
            }, this.eventEmitter, scopes, user);
        };
    }

    /**
     * Assign this function to the 'token' endpoint with POST method.
     * Recommended endpoint: POST /api/oauth/v2/token
     */
    public token(): ExpressMiddleware {
        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {grant_type} = req.body;

            if (!grant_type)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Body parameter grant_type is missing'
                });

            let imp = this.implementations.find(imp => imp.endpoint === 'token' && imp.matchType === grant_type);
            if (!imp) {
                this.eventEmitter.emit(Events.TOKEN_GRANT_TYPE_UNSUPPORTED, req);
                return error(res, {
                    error: 'unsupported_grant_type',
                    error_description: `Grant type ${grant_type} is not supported`,
                    error_uri: this.options.errorUri
                });
            }

            imp.function(req, {...this.options}, this.issueRefreshToken, (response, err) => {
                if (err)
                    return error(res, {
                        error: err.error,
                        error_description: err.error_description,
                        error_uri: err.error_uri ? err.error_uri : this.options.errorUri,
                        status: err.status
                    });

                res.header('Cache-Control', 'no-store').status(200).json(response);
            }, this.eventEmitter, undefined, undefined);
        };
    }

    /**
     * Assign this function to the 'device' endpoint with POST method.
     * Recommended endpoint: POST /api/oauth/v2/device
     */
    public device(): ExpressMiddleware {
        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {grant_type} = req.body;

            if (!grant_type)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Body parameter grant_type is missing'
                });

            let imp = this.implementations.find(imp => imp.endpoint === 'device' && imp.matchType === grant_type);
            if (!imp) {
                this.eventEmitter.emit(Events.DEVICE_GRANT_TYPE_UNSUPPORTED, req);
                return error(res, {
                    error: 'unsupported_grant_type',
                    error_description: `Grant type ${grant_type} is not supported`,
                    error_uri: this.options.errorUri
                });
            }

            imp.function(req, {...this.options}, this.issueRefreshToken, (response, err) => {
                if (err)
                    return error(res, {
                        error: err.error,
                        error_description: err.error_description,
                        error_uri: err.error_uri ? err.error_uri : this.options.errorUri,
                        status: err.status
                    });

                res.header('Cache-Control', 'no-store').status(200).json(response);
            }, this.eventEmitter, undefined, undefined);
        };
    }

    /**
     * This function will be used to authenticate a request if the resource and authorization server
     * are one and the same. If they are different checkout the introspection endpoint.
     * @param scope The scopes needed for this request. If the access token scopes are insufficient
     *              then the authentication will fail. If scope is not initialized then the scope
     *              check will be omitted.
     */
    public authenticate(scope?: string | string[]): ExpressMiddleware {
        let scopes: string[] | undefined = Array.isArray(scope) ? scope : scope?.split(/, */);
        return async (req, res, next) => {
            let token = this.options.getToken(req);
            if (!token) {
                this.eventEmitter.emit(Events.AUTHENTICATION_TOKEN_MISSING, req);
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'No access token was provided',
                    error_uri: this.options.errorUri,
                    noCache: false
                });
            }

            let payload: any = verifyToken(token, this.options.secret);
            if (!payload) {
                this.eventEmitter.emit(Events.AUTHENTICATION_TOKEN_JWT_EXPIRED, req);
                return error(res, {
                    error: 'invalid_token',
                    error_description: 'The access token has expired',
                    error_uri: this.options.errorUri,
                    status: 401,
                    noCache: false
                });
            }

            if(payload.type !== 'access_token') {
                this.eventEmitter.emit(Events.AUTHENTICATION_TOKEN_NOT_ACCESS_TOKEN, req);
                return error(res, {
                    error: 'invalid_token',
                    error_description: 'The token is not an access token',
                    error_uri: this.options.errorUri,
                    status: 401,
                    noCache: false
                });
            }

            if (scopes && payload.scopes.some((v: string) => !scopes!.includes(v))) {
                this.eventEmitter.emit(Events.AUTHENTICATION_SCOPES_INVALID, req);
                return error(res, {
                    error: 'insufficient_scope',
                    error_description: 'Client does not have access to this endpoint',
                    error_uri: this.options.errorUri,
                    status: 403,
                    noCache: false
                });
            }

            let dbToken = await this.options.getAccessToken({
                accessToken: token,
                clientId: payload.client_id,
                user: payload.user
            });

            if (!dbToken || dbToken !== token) {
                this.eventEmitter.emit(Events.AUTHENTICATION_TOKEN_DB_EXPIRED, req);
                return error(res, {
                    error: 'invalid_token',
                    error_description: 'The access token has expired',
                    error_uri: this.options.errorUri,
                    status: 401,
                    noCache: false
                });
            }

            this.options.setPayloadLocation(req, {
                clientId: payload.client_id,
                user: payload.user,
                scopes: payload.scopes,
            });
            next();
        };
    }

    /**
     * Assign this function to the 'introspection' endpoint with POST method.
     * This endpoint is meant to be accessible only by the resource servers, if you make this endpoint
     * public make sure to verify the client on your own before the request reach this function.
     * Recommended endpoint: POST /api/oauth/v2/introspection
     */
    public introspection(): ExpressMiddleware {
        const inactive = (res: any): void => {
            res.status(200).json({active: false});
        }

        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {token} = req.body;
            if (!token) return inactive(res);

            let payload: any = verifyToken(token, this.options.secret);
            if (!payload) return inactive(res);

            let dbToken = await this.options.getAccessToken({
                accessToken: token,
                clientId: payload.client_id,
                user: payload.user
            });

            if (!dbToken || dbToken !== token)
                return inactive(res);

            res.status(200).json({
                active: true,
                scope: payload.scopes.join(this.options.scopeDelimiter),
                client_id: payload.client_id,
                user: payload.user,
                exp: payload.exp,
                token_type: 'Bearer'
            });
        }
    }
}