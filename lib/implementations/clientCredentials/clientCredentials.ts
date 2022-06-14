import {Implementation} from "../../components/implementation";
import {generateARTokens, getTokenExpiresAt} from "../../modules/tokenUtils";
import {ClientCredentialsOptions} from "./clientCredentialsOptions";
import {Events} from "../../components/events";

export function clientCredentials(options: ClientCredentialsOptions): Implementation {
    let opts = {...options};

    if (typeof opts.validateClient !== 'function')
        throw new Error('validateClient is not a function');

    return {
        name: 'client-credentials',
        endpoint: 'token',
        matchType: 'client_credentials',
        function: async (data, callback, eventEmitter) => {
            let {client_id, client_secret} = (data.serverOpts.getClientCredentials as any)(data.req);
            const {scope} = data.req.body;

            // Validate scopes
            let scopes = scope?.split(' ') || [];
            if (!(await data.serverOpts.validateScopes(scopes))) {
                eventEmitter.emit(Events.TOKEN_FLOWS_CLIENT_CREDENTIALS_SCOPES_INVALID, data.req);
                return callback(undefined, {
                    error: 'invalid_scope',
                    error_description: 'One or more scopes are not acceptable'
                });
            }

            // Validate client
            if (!(await opts.validateClient(client_id, client_secret))) {
                eventEmitter.emit(Events.TOKEN_FLOWS_CLIENT_CREDENTIALS_CLIENT_INVALID, data.req);
                return callback(undefined, {
                    error: 'unauthorized_client',
                    error_description: 'Client authentication failed'
                });
            }

            // Generate access token
            let tokens = generateARTokens({}, client_id, scopes, data.serverOpts, false);

            // Save to database
            let dbRes = await data.serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.accessTokenLifetime!, 'access'),
                clientId: client_id,
                scopes,
            }, data.req);

            if (!dbRes) {
                eventEmitter.emit(Events.TOKEN_FLOWS_CLIENT_CREDENTIALS_SAVE_ERROR, data.req);
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error'
                });
            }

            // Respond with access token
            callback(tokens);
        }
    }
}