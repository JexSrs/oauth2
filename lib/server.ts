import { nanoid } from "nanoid";
import {ServerOptions} from "./components/serverOptions";
import {ExpressMiddleware} from "./components/types";
import {verifyToken, signToken} from "./modules/utils";
import {memory} from "./modules/memory";

export class Server {

    private readonly options: ServerOptions;

    constructor(options?: Partial<ServerOptions>) {
        let opts: Partial<ServerOptions> = options || {};

        if(!opts.getToken)
            opts.getToken = (req) => req.headers['authorization'];
        if(!opts.secret)
            opts.secret = nanoid(64);
        if(!opts.tokenUtils)
            opts.tokenUtils = {
                sign: (payload, expiresIn) => signToken(payload, opts.secret, expiresIn),
                verify: token => verifyToken(token, opts.secret),
            };
        if(typeof opts.accessTokenLifetime !== 'undefined') {
            if(opts.accessTokenLifetime <= 0 || Math.trunc(opts.accessTokenLifetime) !== opts.accessTokenLifetime)
                throw new Error('accessTokenLifetime is not positive integer.')
        } else opts.accessTokenLifetime = 86400;

        if(typeof opts.allowRefreshToken === 'undefined')
            opts.allowRefreshToken = true;

        if (typeof opts.refreshTokenLifetime === 'undefined')
            opts.refreshTokenLifetime = 864000;
        else if (opts.refreshTokenLifetime <= 0 || Math.trunc(opts.refreshTokenLifetime) !== opts.refreshTokenLifetime)
                throw new Error('refreshTokenLifetime is not positive integer.')

        if (typeof opts.authorizationCodeLifetime === 'undefined')
            opts.authorizationCodeLifetime = 864000;
        else if (opts.authorizationCodeLifetime <= 0 || Math.trunc(opts.authorizationCodeLifetime) !== opts.authorizationCodeLifetime)
            throw new Error('authorizationCodeLifetime is not positive integer.')

        if(!opts.payloadLocation)
            opts.payloadLocation = (req, payload) => req.oauth2 = payload;

        if(!opts.setPayload)
            opts.setPayload = req => req.headers['authorization'].split(' ')[1].split(':')[0];

        if(!opts.database)
            opts.database = memory();

        this.options = opts as ServerOptions;
    }

    public authorize(): ExpressMiddleware {
        return (req, res, next) => {
            let grantType = req.body.response_type;

            switch (grantType) {
                case 'code': // Authorization Code
                    break;
                case 'token': // Implicit Grant
                    break;
                case 'password': // Resource Owner Credentials
                    break;
                case 'client_credentials': // Client Credentials
                    break;
                case 'refresh_token': // Refresh Token
                    break;
                default: // THROW ERROR
            }
        };
    }

    public authenticate(): ExpressMiddleware {
        return (req, res, next) => {

        };
    }
}