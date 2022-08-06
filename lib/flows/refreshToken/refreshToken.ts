import {Flow} from "../../components/flow";
import {generateARTokens, getTokenExpiresAt, verifyToken} from "../../utils/tokenUtils";
import {RefreshTokenOptions} from "./rtOptions.js";
import {Events} from "../../components/events";

export function refreshToken(opts?: RefreshTokenOptions): Flow {
    const options = Object.assign({}, opts);
    
    return {
        name: 'refresh-token',
        endpoint: 'token',
        matchType: 'refresh_token',
        function: async (data, callback, eventEmitter) => {
            let {scope, refresh_token} = data.req.body;

            if (!refresh_token)
                return callback(undefined, {
                    error: 'invalid_request',
                    error_description: 'Body parameter refresh_token is missing',
                    error_uri: options.errorUri
                });

            // Verify refresh token
            let refreshTokenPayload: any = verifyToken(refresh_token, data.serverOpts.secret, data.serverOpts.issuer, data.serverOpts.issuer);
            if (!refreshTokenPayload) {
                eventEmitter.emit(Events.INVALID_REFRESH_TOKEN_JWT, data.req);
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: 'The refresh token has expired',
                    error_uri: options.errorUri
                });
            }

            if (refreshTokenPayload.type !== 'refresh_token') {
                eventEmitter.emit(Events.INVALID_REFRESH_TOKEN_NOT, data.req);
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: 'Provided token is not a refresh token',
                    error_uri: options.errorUri
                });
            }

            // Scope is optional - Set as scopes the ones we know
            let scopes: string[] = refreshTokenPayload.scopes;
            if (scope) {
                // Check scopes - No need to check with app because the new scopes must
                // be subset of the refreshTokenPayload.scopes
                scopes = scope.split(data.serverOpts.scopeDelimiter);
                if (refreshTokenPayload.scopes.some((v: any) => !scopes.includes(v))) {
                    eventEmitter.emit(Events.INVALID_REFRESH_TOKEN_SCOPES, data.req);
                    return callback(undefined, {
                        error: 'invalid_scope',
                        error_description: 'One or more scopes are not acceptable',
                        error_uri: options.errorUri
                    });
                }
            }

            // Verify refresh token payload
            if (refreshTokenPayload.client_id !== data.clientId) {
                eventEmitter.emit(Events.INVALID_REFRESH_TOKEN_CLIENT, data.req);
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: `This refresh token does not belong to client ${data.clientId}`,
                    error_uri: options.errorUri
                });
            }

            // Validate database
            let dbToken = await data.serverOpts.getRefreshToken({
                refreshToken: refresh_token,
                clientId: data.clientId,
                user: refreshTokenPayload.user,
            }, data.req);

            if (!dbToken || dbToken !== refresh_token) {
                eventEmitter.emit(Events.INVALID_REFRESH_TOKEN_DB, data.req);
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: 'The refresh token has expired',
                    error_uri: options.errorUri
                });
            }

            // Remove old tokens from database
            await data.serverOpts.revoke({
                what: 'record',
                refreshToken: refresh_token,
                clientId: data.clientId,
                user: refreshTokenPayload.user
            }, data.req);

            // Generate new tokens
            let tokens = await generateARTokens(data.req, {user: refreshTokenPayload.user}, data.clientId, scopes, data.serverOpts, data.issueRefreshToken);

            // Database save
            let dbRes = await data.serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.accessTokenLifetime!, 'access'),
                refreshToken: tokens.refresh_token,
                refreshTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.refreshTokenLifetime!, 'refresh'),
                clientId: data.clientId,
                user: refreshTokenPayload.user,
                scopes,
            }, data.req);

            if (!dbRes) {
                eventEmitter.emit(Events.FAILED_TOKEN_SAVE, data.req);
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error',
                    error_uri: options.errorUri
                });
            }

            callback(tokens);
        }
    }
}