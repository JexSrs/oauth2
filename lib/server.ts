import {ServerOptions} from "./components/serverOptions";
import {ExpressMiddleware} from "./components/types";
import {
    allowedMethod,
    generateARTokens,
    getCredentials,
    objToParams,
    parseScopes,
    signToken,
    verifyToken
} from "./modules/utils";
import {memory} from "./modules/memory";


export class Server {

    private readonly options: ServerOptions;

    constructor(options?: ServerOptions) {
        let opts: Partial<ServerOptions> = options || {};

        if (!opts.allowedGrantTypes)
            opts.allowedGrantTypes = ['authorization-code', 'resource-owner-credentials', 'refresh-token'];

        if (!opts.getToken)
            opts.getToken = (req) => req.headers['authorization'];

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

        if (!opts.getUser)
            opts.getUser = req => {
                return {};
            };

        if (!opts.database)
            opts.database = memory();

        if (!opts.scopeDelimiter)
            opts.scopeDelimiter = ' ';

        if (!opts.minStateLength)
            opts.minStateLength = 8;

        this.options = opts as ServerOptions;
    }

    private async authorizationCode1(req: any, res: any): Promise<void> {
        let {client_id, state, redirect_uri, scope} = req.params;

        // Check if state exists and is at least 8 chars
        if (state.length < this.options.minStateLength)
            return res.status(401).end(`state must be at least ${this.options.minStateLength} characters`);

        // Check scopes
        let scopes: string[] | null;
        if ((scopes = await parseScopes(scope, 'authorization-code', this.options)) == null)
            return res.status(401).end('One or more scopes are not acceptable');

        if (!client_id || !redirect_uri)
            return res.status(401).end('Missing parameters.');

        // Validate redirect_uri & client_id
        if (!(await this.options.validateRedirectUri(client_id, redirect_uri)))
            return res.status(401).end('redirect_uri is not registered');

        // Checks are done, generate authorization code
        let user = this.options.getUser(req);
        let payload = {client_id, user};
        let code = signToken(payload, this.options.secret, this.options.authorizationCodeLifetime);
        await this.options.database.saveAuthorizationCode({
            authorizationCode: code,
            clientId: client_id,
            scopes,
            user,
            redirect_uri,
            expiresAt: Math.trunc((Date.now() + this.options.authorizationCodeLifetime * 1000) / 1000),
        });

        res.redirect(`${redirect_uri}?code=${code}&state=${state}`);
    }

    private async authorizationCode2(req: any, res: any): Promise<void> {
        let {client_id, client_secret} = getCredentials(req);
        let {code, redirect_uri} = req.body;

        // Token verification
        let authCodePayload: any = verifyToken(code, this.options.secret);
        if (!authCodePayload) return res.status(401).end('Authorization code is not valid.');

        // Payload verification
        if (authCodePayload.client_id !== client_id)
            return res.status(401).end('Authorization code does not belong to authenticated client.');

        // Do database request at last to lessen db costs.
        if (!(await this.options.validateClient(client_id, client_secret)))
            return res.status(403).end('Client authentication failed.');

        // Database verification
        let dbCode = await this.options.database.loadAuthorizationCode({
            clientId: client_id,
            authorizationCode: code,
            expiresAt: authCodePayload.exp
        });

        if (!dbCode || dbCode.authorizationCode !== code)
            return res.status(401).end('Authorization code is not valid.');

        if (redirect_uri !== dbCode.redirect_uri)
            return res.status(401).end('redirect_uri is not valid.');

        // Database delete
        await this.options.database.removeAuthorizationCode({
            clientId: client_id,
            authorizationCode: code,
            expiresAt: authCodePayload.exp
        });

        // Generate access & refresh tokens
        let response = await generateARTokens({
            client_id,
            user: dbCode.user
        }, authCodePayload.scopes, req, this.options);
        res.status(200).json(response);
    }

    private async implicit(req: any, res: any): Promise<void> {
        let {client_id, state, redirect_uri, scope} = req.params;

        // Check if state exists and is at least 8 chars
        if (state.length < this.options.minStateLength)
            return res.status(422).end(`state must be at least ${this.options.minStateLength} characters`);

        // Check scopes
        let scopes: string[] | null;
        if ((scopes = await parseScopes(scope, 'implicit', this.options)) == null)
            return res.status(422).end('One or more scopes are not acceptable');

        // Validate redirect_uri & client_id
        if (!(await this.options.validateRedirectUri(client_id, redirect_uri)))
            return res.status(401).end('redirect_uri is not registered');

        let user = this.options.getUser(req);
        let payload = {client_id, user};
        // Generate access & refresh tokens
        let response = await generateARTokens(payload, scopes, req, this.options);
        res.redirect(`${redirect_uri}${objToParams(response)}`);
    }

    private async resourceOwnerCredentials(req: any, res: any): Promise<void> {
        let {client_id, client_secret} = getCredentials(req);
        let {username, password, scope} = req.body; // user validation is not going to happen
                                                    // from the library (e.x. SRP implementation)
        // Check scopes
        let scopes: string[] | null;
        if ((scopes = await parseScopes(scope, 'resource-owner-credentials', this.options)) == null)
            return res.status(422).end('One or more scopes are not acceptable');

        // Do database request at last to lessen db costs.
        if (!(await this.options.validateClient(client_id, client_secret)))
            return res.status(403).end('Client authentication failed.');

        let user = this.options.getUser(req);
        let payload = {client_id, user};
        // Generate access & refresh tokens
        let response = await generateARTokens(payload, scopes, req, this.options);
        res.status(200).json(response);
    }

    private async clientCredentials(req: any, res: any): Promise<void> {
        let {client_id, client_secret} = getCredentials(req);
        let {scope} = req.body;

        // Check scopes
        let scopes: string[] | null;
        if ((scopes = await parseScopes(scope, 'client-credentials', this.options)) == null)
            return res.status(422).end('One or more scopes are not acceptable');

        // Do database request at last to lessen db costs.
        if (!(await this.options.validateClient(client_id, client_secret)))
            return res.status(403).end('Client authentication failed.');

        // Generate access & refresh tokens
        let response = await generateARTokens({client_id}, scopes, req, this.options);
        delete response.refresh_token;
        delete response.refresh_token_expires_in;
        res.status(200).json(response);
    }

    private async refreshToken(req: any, res: any): Promise<void> {
        let {client_id, client_secret} = getCredentials(req);
        let {scope, refresh_token} = req.body;

        // Check scopes
        let scopes: string[] | null;
        if ((scopes = await parseScopes(scope, 'refresh-token', this.options)) == null)
            return res.status(422).end('One or more scopes are not acceptable');

        let refreshTokenPayload: object | null = verifyToken(refresh_token, this.options.secret);
        if (!refreshTokenPayload)
            return res.status(422).end('Refresh token is not valid');

        // Do database request at last to lessen db costs.
        if (!(await this.options.validateClient(client_id, client_secret)))
            return res.status(403).end('Client authentication failed.');

        // Generate tokens
        // Remove tokens
        // Add new tokens

        // let response = await generateARTokens(client_id, scopes, req, this.options);
        // res.status(200).json(response);
    }

    public authorize(): ExpressMiddleware {
        return (req, res, next) => {
            let responseType = req.params.response_type;
            switch (responseType) {
                case 'code': // Authorization Code - step 1
                    allowedMethod(req, res, 'GET', this.authorizationCode1.bind(this))
                    break;
                case 'token': // Implicit Grant
                    allowedMethod(req, res, 'GET', this.implicit.bind(this))
                    break;
                default: // THROW ERROR
                    res.status(422).end('Invalid response_type.');
            }
        };
    }

    public token(): ExpressMiddleware {
        return (req, res, next) => {
            let grantType = req.body.grant_type;
            switch (grantType) {
                case 'authorization_code': // Authorization Code - step 2
                    allowedMethod(req, res, 'POST', this.authorizationCode2.bind(this))
                    break;
                case 'password': // Resource Owner Credentials
                    allowedMethod(req, res, 'POST', this.resourceOwnerCredentials.bind(this))
                    break;
                case 'client_credentials': // Client Credentials
                    allowedMethod(req, res, 'POST', this.clientCredentials.bind(this))
                    break;
                case 'refresh_token': // Refresh Token
                    allowedMethod(req, res, 'POST', this.refreshToken.bind(this))
                    break;
                default: // THROW ERROR
                    res.status(422).end('Invalid grant_type.');
            }
        };
    }

    public authenticate(): ExpressMiddleware {
        return (req, res, next) => {

        };
    }
}

// CL_ID: bJB3Ew6UAw0Ylc6f6oLCMzGw
// CL_SC: eVYsXtk-269Zo1en07T4CTCdJWLQU65zF-Jn85rgCZm4Gq6B

// US_US: clear-cormorant@example.com
// US_PS: Bad-Kouprey-60