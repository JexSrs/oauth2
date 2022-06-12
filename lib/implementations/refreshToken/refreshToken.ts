import {Implementation} from "../../components/implementation";
import {generateARTokens, verifyToken, getTokenExpiresAt} from "../../modules/tokenUtils";
import {RefreshTokenOptions} from "./refreshTokenOptions";
import {Events} from "../../components/events";

export function refreshToken(options: RefreshTokenOptions): Implementation {
    let opts = {...options};

    if(typeof opts.getRefreshToken !== 'function')
        throw new Error('getRefreshToken is not a function');
    if(typeof opts.deleteTokens !== 'function')
        throw new Error('deleteTokens is not a function');

    if(typeof opts.validateClient !== 'function')
        throw new Error('validateClient is not a function');

    return {
        name: 'refresh-token',
        endpoint: 'token',
        matchType: 'refresh_token',
        function: async (data, callback, eventEmitter) => {
            let {client_id, client_secret} = (data.serverOpts.getClientCredentials as any)(data.req);
            let {scope, refresh_token} = data.req.body;
            // if (!client_id) client_id = req.body.client_id;

            if(!refresh_token)
                return callback(undefined, {
                    error: 'invalid_request',
                    error_description: 'Body parameter refresh_token is missing'
                });

            // Verify refresh token
            let refreshTokenPayload: any = verifyToken(refresh_token, data.serverOpts.secret);
            if (!refreshTokenPayload) {
                eventEmitter.emit(Events.TOKEN_FLOWS_REFRESH_TOKEN_TOKEN_JWT_INVALID, data.req);
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: 'The refresh token has expired'
                });
            }

            if(refreshTokenPayload.type !== 'refresh_token') {
                eventEmitter.emit(Events.TOKEN_FLOWS_REFRESH_TOKEN_TOKEN_NOT_REFRESH_TOKEN, data.req);
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: 'Provided token is not a refresh token'
                });
            }

            // Scope is optional
            let scopes: string[] = refreshTokenPayload.scopes;
            if(scope) {
                // Check scopes - No need to check with app because the new scopes must
                // be subset of the refreshTokenPayload.scopes
                scopes = scope.split(data.serverOpts.scopeDelimiter);
                if (refreshTokenPayload.scopes.some((v: any) => !scopes.includes(v))) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_REFRESH_TOKEN_SCOPES_INVALID, data.req);
                    return callback(undefined, {
                        error: 'invalid_scope',
                        error_description: 'One or more scopes are not acceptable'
                    });
                }
            }

            // Verify refresh token payload
            if (refreshTokenPayload.client_id !== client_id) {
                eventEmitter.emit(Events.TOKEN_FLOWS_REFRESH_TOKEN_CLIENT_INVALID, data.req);
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: `This refresh token does not belong to client ${client_id}`
                });
            }

            // Validate client
            if (!(await opts.validateClient(client_id, client_secret))) {
                eventEmitter.emit(Events.TOKEN_FLOWS_REFRESH_TOKEN_CLIENT_INVALID, data.req);
                return callback(undefined, {
                    error: 'unauthorized_client',
                    error_description: 'Client authentication failed'
                });
            }

            // Validate database
            let dbToken = await opts.getRefreshToken({
                refreshToken: refresh_token,
                clientId: client_id,
                user: refreshTokenPayload.user,
            });

            if (!dbToken || dbToken !== refresh_token) {
                eventEmitter.emit(Events.TOKEN_FLOWS_REFRESH_TOKEN_TOKEN_DB_INVALID, data.req);
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: 'The refresh token has expired'
                });
            }

            // Remove old tokens from database
            await opts.deleteTokens({
                refreshToken: refresh_token,
                clientId: client_id,
                user: refreshTokenPayload.user
            });

            // Generate new tokens
            let tokens = generateARTokens({
                user: refreshTokenPayload.user
            }, client_id, scopes, data.serverOpts, data.issueRefreshToken);

            // Database save
            let dbRes = await data.serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.accessTokenLifetime!, 'access'),
                refreshToken: tokens.refresh_token,
                refreshTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.refreshTokenLifetime!, 'refresh'),
                clientId: client_id,
                user: refreshTokenPayload.user,
                scopes,
            });

            if(!dbRes) {
                eventEmitter.emit(Events.TOKEN_FLOWS_REFRESH_TOKEN_SAVE_ERROR, data.req);
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error',
                });
            }

            callback(tokens);
        }
    }
}