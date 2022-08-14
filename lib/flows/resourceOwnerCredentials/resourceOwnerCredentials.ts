import {Flow} from "../../components/flow";
import {generateARTokens, getTokenExpiresAt} from "../../utils/tokenUtils";
import {ResourceOwnerCredentialsOptions} from "./rocOptions.js";
import {Events} from "../../components/events";

export function resourceOwnerCredentials(opts: ResourceOwnerCredentialsOptions): Flow {
    const options = Object.assign({}, opts);

    if (typeof opts.validateUser !== 'function')
        throw new Error('validateUser is not a function');

    return {
        name: 'resource-owner-credentials',
        endpoint: 'token',
        matchType: 'password',
        function: async (data, eventEmitter) => {
            const {scope, username, password} = data.req.body;

            if (!username)
                return {
                    error: 'invalid_request',
                    error_description: 'Body parameter username is missing',
                    error_uri: options.errorUri
                };

            if (!password)
                return {
                    error: 'invalid_request',
                    error_description: 'Body parameter password is missing',
                    error_uri: options.errorUri
                };

            let scopes = scope?.split(' ') || [];
            const scopeResult = await data.serverOpts.validateScopes(scopes, data.req);
            if(Array.isArray(scopeResult))
                scopes = scopeResult;
            else if (scopeResult === false) {
                eventEmitter.emit(Events.INVALID_SCOPES, data.req);
                return {
                    error: 'invalid_scope',
                    error_description: 'One or more scopes are not acceptable',
                    error_uri: options.errorUri
                };
            }

            let user = await opts.validateUser(username, password, data.req);
            if (user == null) {
                eventEmitter.emit(Events.INVALID_USER, data.req);
                return {
                    error: 'invalid_grant',
                    error_description: 'User authentication failed',
                    error_uri: options.errorUri
                };
            }

            // Generate access & refresh tokens
            let tokens = await generateARTokens({
                req: data.req,
                payload: {
                    user
                },
                clientId: data.clientId,
                scopes,
                opts: data.serverOpts,
                issueRefreshToken: data.issueRefreshToken
            });

            // Database save
            let dbRes = await data.serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.accessTokenLifetime!, 'access'),
                refreshToken: tokens.refresh_token,
                refreshTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.refreshTokenLifetime!, 'refresh'),
                clientId: data.clientId,
                user,
                scopes,
            }, data.req);

            if (!dbRes) {
                eventEmitter.emit(Events.FAILED_TOKEN_SAVE, data.req);
                return {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error',
                    error_uri: options.errorUri
                };
            }

            return tokens;
        }
    }
}