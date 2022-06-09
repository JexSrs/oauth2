import {Implementation} from "../components/implementation";
import {generateARTokens, getTokenExpiresAt} from "../modules/tokenUtils";
import {ResourceOwnerCredentialsOptions} from "../components/options/implementations/resourceOwnerCredentialsOptions";
import {defaultCommonOpts} from "../modules/utils";
import {Events} from "../components/events";

export function resourceOwnerCredentials(options: ResourceOwnerCredentialsOptions): Implementation {
    let opts = {...options, ...defaultCommonOpts(options)};

    if(typeof opts.validateUser !== 'function')
        throw new Error('validateUser is not a function');

    return {
        name: 'resource-owner-credentials',
        endpoint: 'token',
        matchType: 'password',
        function: async (req, serverOpts, issueRefreshToken, callback, eventEmitter) => {
            let {client_id, client_secret} = (serverOpts.getClientCredentials as any)(req);
            const {scope, username, password} = req.body;

            if(!username)
                return callback(undefined, {
                    error: 'invalid_request',
                    error_description: 'Body parameter username is missing'
                });

            if(!password)
                return callback(undefined, {
                    error: 'invalid_request',
                    error_description: 'Body parameter password is missing'
                });

            let scopes = scope?.split(serverOpts.scopeDelimiter) || [];
            if (!(await serverOpts.isScopesValid(scopes))) {
                eventEmitter.emit(Events.TOKEN_FLOWS_PASSWORD_SCOPES_INVALID, req);
                return callback(undefined, {
                    error: 'invalid_scope',
                    error_description: 'One or more scopes are not acceptable'
                });
            }

            // Do database request at last to lessen db costs.
            if (!(await opts.validateClient(client_id, client_secret))) {
                eventEmitter.emit(Events.TOKEN_FLOWS_PASSWORD_CLIENT_INVALID, req);
                return callback(undefined, {
                    error: 'unauthorized_client',
                    error_description: 'Client authentication failed'
                });
            }

            let user = await opts.validateUser(username, password);
            if (!user) {
                eventEmitter.emit(Events.TOKEN_FLOWS_PASSWORD_USER_INVALID, req);
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: 'User authentication failed'
                });
            }

            // Generate access & refresh tokens
            let tokens = await generateARTokens({user}, client_id, scopes, serverOpts, issueRefreshToken);

            // Database save
            let dbRes = await serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: getTokenExpiresAt(tokens, serverOpts.accessTokenLifetime!, 'access'),
                refreshToken: tokens.refresh_token,
                refreshTokenExpiresAt: getTokenExpiresAt(tokens, serverOpts.refreshTokenLifetime!, 'refresh'),
                clientId: client_id,
                user,
                scopes,
            });

            if(!dbRes) {
                eventEmitter.emit(Events.TOKEN_FLOWS_PASSWORD_SAVE_ERROR, req);
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error',
                });
            }

            callback(tokens);
        }
    }
}