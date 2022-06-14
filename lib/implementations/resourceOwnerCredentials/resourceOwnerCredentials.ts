import {Implementation} from "../../components/implementation";
import {generateARTokens, getTokenExpiresAt} from "../../modules/tokenUtils";
import {ResourceOwnerCredentialsOptions} from "./resourceOwnerCredentialsOptions";
import {Events} from "../../components/events";

export function resourceOwnerCredentials(options: ResourceOwnerCredentialsOptions): Implementation {
    let opts = {...options};

    if (typeof opts.validateUser !== 'function')
        throw new Error('validateUser is not a function');

    if (typeof opts.validateClient !== 'function')
        throw new Error('validateClient is not a function');

    return {
        name: 'resource-owner-credentials',
        endpoint: 'token',
        matchType: 'password',
        function: async (data, callback, eventEmitter) => {
            let {client_id, client_secret} = (data.serverOpts.getClientCredentials as any)(data.req);
            const {scope, username, password} = data.req.body;

            if (!username)
                return callback(undefined, {
                    error: 'invalid_request',
                    error_description: 'Body parameter username is missing'
                });

            if (!password)
                return callback(undefined, {
                    error: 'invalid_request',
                    error_description: 'Body parameter password is missing'
                });

            let scopes = scope?.split(data.serverOpts.scopeDelimiter) || [];
            if (!(await data.serverOpts.validateScopes(scopes))) {
                eventEmitter.emit(Events.TOKEN_FLOWS_PASSWORD_SCOPES_INVALID, data.req);
                return callback(undefined, {
                    error: 'invalid_scope',
                    error_description: 'One or more scopes are not acceptable'
                });
            }

            // Do database request at last to lessen db costs.
            if (!(await opts.validateClient(client_id, client_secret))) {
                eventEmitter.emit(Events.TOKEN_FLOWS_PASSWORD_CLIENT_INVALID, data.req);
                return callback(undefined, {
                    error: 'unauthorized_client',
                    error_description: 'Client authentication failed'
                });
            }

            let user = await opts.validateUser(username, password);
            if (!user) {
                eventEmitter.emit(Events.TOKEN_FLOWS_PASSWORD_USER_INVALID, data.req);
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: 'User authentication failed'
                });
            }

            // Generate access & refresh tokens
            let tokens = generateARTokens({user}, client_id, scopes, data.serverOpts, data.issueRefreshToken);

            // Database save
            let dbRes = await data.serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.accessTokenLifetime!, 'access'),
                refreshToken: tokens.refresh_token,
                refreshTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.refreshTokenLifetime!, 'refresh'),
                clientId: client_id,
                user,
                scopes,
            }, data.req);

            if (!dbRes) {
                eventEmitter.emit(Events.TOKEN_FLOWS_PASSWORD_SAVE_ERROR, data.req);
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error',
                });
            }

            callback(tokens);
        }
    }
}