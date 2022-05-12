import {nanoid} from "nanoid";
import {ServerOptions} from "./components/serverOptions";
import {ExpressMiddleware} from "./components/types";
import {generateARTokens, signToken, someAsync, verifyToken} from "./modules/utils";
import {memory} from "./modules/memory";

export class Server {

    private readonly options: ServerOptions;

    constructor(options?: Partial<ServerOptions>) {
        let opts: Partial<ServerOptions> = options || {};

        if (!opts.getToken)
            opts.getToken = (req) => req.headers['authorization'];
        if (!opts.secret) {
            console.log('CAUTION! You are not using a personal secret, on app restart it will be overwritten.');
            opts.secret = nanoid(64);
        }
        if (!opts.tokenUtils)
            opts.tokenUtils = {
                sign: (payload, expiresIn) => signToken(payload, opts.secret, expiresIn),
                verify: token => {
                    try {
                        return verifyToken(token, opts.secret);
                    } catch (e) {
                        return null;
                    }
                },
            };
        if (typeof opts.accessTokenLifetime !== 'undefined') {
            if (opts.accessTokenLifetime <= 0 || Math.trunc(opts.accessTokenLifetime) !== opts.accessTokenLifetime)
                throw new Error('accessTokenLifetime is not positive integer.')
        } else opts.accessTokenLifetime = 86400;

        if (typeof opts.allowRefreshToken === 'undefined')
            opts.allowRefreshToken = true;

        if (typeof opts.refreshTokenLifetime === 'undefined')
            opts.refreshTokenLifetime = 864000;
        else if (opts.refreshTokenLifetime <= 0 || Math.trunc(opts.refreshTokenLifetime) !== opts.refreshTokenLifetime)
            throw new Error('refreshTokenLifetime is not positive integer.')

        if (typeof opts.authorizationCodeLifetime === 'undefined')
            opts.authorizationCodeLifetime = 864000;
        else if (opts.authorizationCodeLifetime <= 0 || Math.trunc(opts.authorizationCodeLifetime) !== opts.authorizationCodeLifetime)
            throw new Error('authorizationCodeLifetime is not positive integer.')

        if (!opts.payloadLocation)
            opts.payloadLocation = (req, payload) => req.oauth2 = payload;

        if (!opts.includeToPayload)
            opts.includeToPayload = req => {return {}};

        if (!opts.database)
            opts.database = memory();

        if (!opts.acceptedScopes)
            opts.acceptedScopes = ['read', 'write'];

        if (!opts.scopeDelimiter)
            opts.scopeDelimiter = ' ';

        if (!opts.minStateLength)
            opts.minStateLength = 8;

        if (!opts.validateClient) {
            console.log('CAUTION! You are not using a personal validateClient function, this will make the OAuth2 authorization available to everyone.');
            opts.validateClient = async (client_id, client_secret, redirect_uri) => true;
        }

        this.options = opts as ServerOptions;
    }

    private async authorizationCode1(req: any, res: any): Promise<void> {
        if (req.method !== 'GET')
            return res.status(405).end('Method not allowed.');

        let {client_id, state, redirect_uri, scope} = req.params;

        // Check if state exists and is at least 8 chars
        if (state.length < this.options.minStateLength)
            return res.status(422).end(`state must be at least ${this.options.minStateLength} characters`);

        // Check scopes
        let scopes: string[] = scope.split(this.options.scopeDelimiter);
        if ((Array.isArray(this.options.acceptedScopes)
                && scopes.some(s => !(this.options.acceptedScopes as string[]).includes(s)))
            || await someAsync(scopes, async s => !(await (this.options.acceptedScopes as any)(s)))
        ) return res.status(422).end('One or more scopes are not acceptable');

        // Validate redirect_uri & client_id
        if (!(await this.options.validateClient(client_id, null, redirect_uri)))
            return res.status(401).end('redirect_uri is not registered');

        // Checks are done, generate authorization code
        let payload = {client_id};
        let code = this.options.tokenUtils.sign(payload, this.options.authorizationCodeLifetime);
        await this.options.database.saveAuthorizationCode({
            authorizationCode: code,
            payload,
            expiresAt: Math.trunc((Date.now() + this.options.authorizationCodeLifetime * 1000) / 1000),
        });

        res.status(200).json({code, state});
    }

    private async authorizationCode2(req: any, res: any): Promise<void> {
        if (req.method !== 'POST')
            return res.status(405).end('Method not allowed.');

        let authHeader = req.headers['authorization'];
        let decoded = authHeader && Buffer.from(authHeader, 'base64').toString()
        if(!decoded) return res.status(403).end('Authorization header is missing');

        let [client_id, client_secret] = /^([^:]*):(.*)$/.exec(decoded);
        if(!client_id || !client_secret) return res.status(403).end('Authorization header is missing');

        let {code, redirect_uri} = req.params;

        // Validate redirect_uri
        if (!redirect_uri) return res.status(401).end('redirect_uri is not registered');

        if(!(await this.options.validateClient(client_id, client_secret, redirect_uri)))
            return res.status(403).end('Client authentication failed.');

        // Token verification
        let authCodePayload: any = this.options.tokenUtils.verify(code);
        if(!authCodePayload) return res.status(401).end('Authorization code is not valid.');

        // Payload verification
        if(authCodePayload.client_id !== client_id)
            return res.status(401).end('Authorization code does not belong to authenticated client.');

        // Database verification
        let dbCode = await this.options.database.loadAuthorizationCode({
            payload: {client_id},
            authorizationCode: code,
            expiresAt: authCodePayload.exp
        });

        if(!dbCode || dbCode !== code)
            return res.status(401).end('Authorization code is not valid.');

        // Database delete
        await this.options.database.removeAuthorizationCode({
            payload: {client_id},
            authorizationCode: code,
            expiresAt: authCodePayload.exp
        });

        // Generate access & refresh tokens
        let response = await generateARTokens(client_id, req, this.options);
        res.status(200).json(response);
    }

    private async implicit(req: any, res: any): Promise<void> {
        if (req.method !== 'GET')
            return res.status(405).end('Method not allowed.');

        let {client_id, state, redirect_uri, scope} = req.params;

        // Check if state exists and is at least 8 chars
        if (state.length < this.options.minStateLength)
            return res.status(422).end(`state must be at least ${this.options.minStateLength} characters`);

        // Check scopes
        let scopes: string[] = scope.split(this.options.scopeDelimiter);
        if ((Array.isArray(this.options.acceptedScopes)
                && scopes.some(s => !(this.options.acceptedScopes as string[]).includes(s)))
            || await someAsync(scopes, async s => !(await (this.options.acceptedScopes as any)(s)))
        ) return res.status(422).end('One or more scopes are not acceptable');

        // Validate redirect_uri & client_id
        if (!(await this.options.validateClient(client_id, null, redirect_uri)))
            return res.status(401).end('redirect_uri is not registered');

        // Generate access & refresh tokens
        let response = await generateARTokens(client_id, req, this.options);
        res.status(200).json(response);
    }

    public authorize(): ExpressMiddleware {
        return (req, res, next) => {
            let grantType = req.params.response_type || req.body.response_type;
            switch (grantType) {
                case 'code': // Authorization Code - step 1
                    this.authorizationCode1(req, res);
                    break;
                case 'authorization_code': // Authorization Code - step 2
                    this.authorizationCode2(req, res);
                    break;
                case 'token': // Implicit Grant
                    this.implicit(req, res);
                    break;
                case 'password': // Resource Owner Credentials
                    break;
                case 'client_credentials': // Client Credentials
                    break;
                case 'refresh_token': // Refresh Token
                    break;
                default: // THROW ERROR
                    res.status(422).end('Invalid response_type (grant type).');
            }
        };
    }

    public authenticate(): ExpressMiddleware {
        return (req, res, next) => {

        };
    }
}