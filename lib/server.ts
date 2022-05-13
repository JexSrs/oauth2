import {ServerOptions} from "./components/serverOptions";
import {ExpressMiddleware} from "./components/types";
import {
    allowedMethod,
    generateARTokens,
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

        if (!opts.grantTypes)
            opts.grantTypes = ['authorization-code', 'resource-owner-credentials', 'refresh-token'];

        if (!opts.getToken)
            opts.getToken = (req) => req.headers['authorization'];

        if (!opts.payloadLocation)
            opts.payloadLocation = (req, payload) => req.payload = payload;

        if (!opts.minStateLength)
            opts.minStateLength = 8;

        if(!opts.getClientCredentials)
            opts.getClientCredentials = (req: any) => {
                let authHeader = req.headers['authorization'];
                let decoded = authHeader
                    && Buffer.from(authHeader, 'base64').toString()
                    || '';

                let [client_id, client_secret] = /^([^:]*):(.*)$/.exec(decoded);
                return {client_id, client_secret};
            };

        if (typeof opts.accessTokenLifetime !== 'undefined') {
            if (opts.accessTokenLifetime <= 0 || Math.trunc(opts.accessTokenLifetime) !== opts.accessTokenLifetime)
                throw new Error('accessTokenLifetime is not positive integer.')
        } else opts.accessTokenLifetime = 86400;

        if (typeof opts.issueRefreshToken === 'undefined')
            opts.issueRefreshToken = opts.grantTypes.includes('refresh-token');

        if (typeof opts.refreshTokenLifetime === 'undefined')
            opts.refreshTokenLifetime = 864000;
        else if (opts.refreshTokenLifetime <= 0 || Math.trunc(opts.refreshTokenLifetime) !== opts.refreshTokenLifetime)
            throw new Error('refreshTokenLifetime is not positive integer.')

        if (typeof opts.authorizationCodeLifetime === 'undefined')
            opts.authorizationCodeLifetime = 864000;
        else if (opts.authorizationCodeLifetime <= 0 || Math.trunc(opts.authorizationCodeLifetime) !== opts.authorizationCodeLifetime)
            throw new Error('authorizationCodeLifetime is not positive integer.')

        if (!opts.tokenHandler)
            opts.tokenHandler = memory();

        if (!opts.scopeDelimiter)
            opts.scopeDelimiter = ' ';

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
        await this.options.tokenHandler.saveAuthorizationCode({
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
        let {client_id, client_secret} = this.options.getClientCredentials(req);
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
        let dbCode = await this.options.tokenHandler.loadAuthorizationCode({
            clientId: client_id,
            authorizationCode: code,
            expiresAt: authCodePayload.exp
        });

        if (!dbCode || dbCode.authorizationCode !== code)
            return res.status(401).end('Authorization code is not valid.');

        if (redirect_uri !== dbCode.redirect_uri)
            return res.status(401).end('redirect_uri is not valid.');

        // Database delete
        await this.options.tokenHandler.removeAuthorizationCode({
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
        // This will be removed in OAuth2.1 because this grant is very limiting
        // and poses security risks.
        // We removed username, password checks to allow other authentication types (such as SRP)
        // and security handling such as brute force attacks.

        let {client_id, client_secret} = this.options.getClientCredentials(req);
        let {username, password, scope} = req.body;

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
        let {client_id, client_secret} = this.options.getClientCredentials(req);
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
        let {client_id, client_secret} = this.options.getClientCredentials(req);
        let {scope, refresh_token} = req.body;
        if(!client_id) client_id = req.body.client_id;

        // Check scopes
        // TODO - Check if scopes are the same or less than before (when created access code)
        let scopes: string[] | null;
        if ((scopes = await parseScopes(scope, 'refresh-token', this.options)) == null)
            return res.status(401).end('One or more scopes are not acceptable');

        let refreshTokenPayload: any = verifyToken(refresh_token, this.options.secret);
        if (!refreshTokenPayload)
            return res.status(401).end('Refresh token is not valid');

        if(refreshTokenPayload.client_id !== client_id)
            return res.status(401).end('Refresh token does not belong to client');

        // If client_secret was passed then verify client (else it will be verified by the access token).
        if (client_secret && !(await this.options.validateClient(client_id, client_secret)))
            return res.status(401).end('Client authentication failed.');

        // Remove old tokens from database
        // TODO - rethink how to remove from database
        await this.options.tokenHandler.removeToken({
            refreshToken: refresh_token,
            refreshTokenExpiresAt: refreshTokenPayload.exp,
            clientId: client_id
        });

        let response = await generateARTokens({client_id}, scopes, req, this.options);
        res.status(200).json(response);
    }

    public authorize(): ExpressMiddleware {
        return (req, res, next) => {
            let responseType = req.params.response_type;
            if(!this.options.grantTypes.includes(responseType)) {
                res.status(422).end('Invalid response_type.');
                return;
            }

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
            if(!this.options.grantTypes.includes(grantType)) {
                res.status(422).end('Invalid grant_type.');
                return;
            }

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