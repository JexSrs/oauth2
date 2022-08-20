import {ResourceServerOptions} from "./components/resourceServer.options.js";
import {ExpressMiddleware} from "./components/general.types.js";
import axios, {AxiosResponse} from "axios";
import {buildQuery, error} from "./utils/general.utils.js";
import {AuthorizationServerOptions} from "./components/authorizationServer.options.js";
import {throws} from "assert";
import {Events} from "./components/events.js";
import {verifyToken} from "./utils/token.utils.js";

export class ResourceServer {

    private readonly options: Required<ResourceServerOptions>;

    constructor(options: ResourceServerOptions) {
        let opts: ResourceServerOptions = Object.assign({}, options);

        if (opts.getToken === undefined)
            opts.getToken = (req) => req.headers['authorization']?.split(' ')?.[1];

        if (opts.setPayloadLocation === undefined)
            opts.setPayloadLocation = (req, payload) => req.payload = payload;

        if(opts.headers === undefined)
            opts.headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            };
        if(opts.body === undefined)
            opts.body = {};

        if(opts.scopeDelimiter === undefined)
            opts.scopeDelimiter = ' ';

        if(opts.introspectionURL === undefined && opts.secret === undefined)
            throw new Error('ResourceServerException introspectionURL or secret must be defined.');

        if(opts.secret !== undefined && opts.issuer === undefined)
            throw new Error('ResourceServerException issuer must be defined.');

        ['audience', 'issuer', 'secret']
            .forEach(field => {
                if((opts as any)[field] === undefined) throw new Error(`ResourceServerException Field ${field} cannot be undefined`);
            });

        this.options = opts as Required<ResourceServerOptions>;
    }

    /**
     * This function will be used to authenticate a request.
     * It will make a request to the authorization server to verify the validity of the access token.
     *
     * It is recommended to cache the response for this endpoint for short periods of time.
     *
     * @param scope The scopes needed for this request. If the access token scopes are insufficient
     *              then the authentication will fail. If scope is not initialized then the scope
     *              check will be omitted.
     * @param cond If more than one scopes are provided, whether the access token must have all of them
     *              or at least one of them.
     * @param overrideOptions
     */
    public authenticate(scope?: string | string[], cond?: 'all' | 'some', overrideOptions?: Partial<ResourceServerOptions>): ExpressMiddleware {
        const options = Object.assign({}, this.options, overrideOptions || {});

        let scopes: string[] | undefined = Array.isArray(scope) ? scope : (scope ? [scope] : undefined);
        let condition = cond || 'all';

        return async (req, res, next) => {
            // Verify JWT token
            const token = options.getToken(req);
            if (!token)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'No access token was provided',
                    error_uri: options.errorUri,
                    noCache: false
                });

            let payload: any = verifyToken(token, options.secret, options.audience, options.issuer);
            if (!payload)
                return error(res, {
                    error: 'invalid_token',
                    error_description: 'The access token has expired',
                    error_uri: options.errorUri,
                    status: 401,
                    noCache: false
                });

            // if((payload.typ !== 'at+jwt' && payload.typ !== 'application/at+jwt') || payload.alg === 'none')
            //     return error(res, {
            //         error: 'invalid_token',
            //         error_description: 'The token is not valid',
            //         error_uri: options.errorUri,
            //         status: 401,
            //         noCache: false
            //     });

            if (payload.type !== 'access_token')
                return error(res, {
                    error: 'invalid_token',
                    error_description: 'The token is not an access token',
                    error_uri: options.errorUri,
                    status: 401,
                    noCache: false
                });

            // Set payload scopes
            let dataScopes = payload.scopes;

            // Introspect if available
            if(options.introspectionURL) {
                let response: AxiosResponse;
                try {
                    response = await axios.post(options.introspectionURL, buildQuery({
                        ...options.body,
                        token,
                    }), {
                        headers: <any>options.headers
                    });
                } catch (e) {
                    // Unexpected errors
                    console.log(e);
                    error(res, {
                        error: 'server_error',
                        error_description: 'Authorization server is not responding or is not reachable.',
                        error_uri: options.errorUri,
                        noCache: false,
                        status: 503
                    });
                    return;
                }

                const data = response.data;

                if(data.active === false)
                    return error(res, {
                        error: 'invalid_token',
                        error_description: 'The access token has expired',
                        error_uri: options.errorUri,
                        status: 401,
                        noCache: false
                    });

                if(data.aud !== options.audience)
                    return error(res, {
                        error: 'invalid_token',
                        error_description: 'The access token is not meant to be used in this resource server',
                        error_uri: options.errorUri,
                        status: 401,
                        noCache: false
                    });

                // Update with scopes from AS.
                dataScopes = data.scope.split(options.scopeDelimiter);
            }

            // Check scopes
            if(scopes) {
                if(
                    (condition === 'all' && scopes.some((v: string) => !dataScopes!.includes(v)))
                    || (condition === 'some' && dataScopes.some((v: string) => !scopes!.includes(v)))
                )
                    return error(res, {
                        error: 'insufficient_scope',
                        error_description: 'Client does not have access to this endpoint',
                        error_uri: options.errorUri,
                        status: 403,
                        noCache: false
                    });
            }

            options.setPayloadLocation(req, payload)
            next();
        };
    }
}