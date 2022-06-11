import {Implementation} from "../components/implementation";
import {generateARTokens, signToken, verifyToken, getTokenExpiresAt} from "../modules/tokenUtils";
import {codeChallengeHash, defaultCommonOpts} from "../modules/utils";
import {AuthorizationCodeOptions} from "../components/options/implementations/authorizationCodeOptions";
import {Events} from "../components/events";

export function authorizationCode(options: AuthorizationCodeOptions): Implementation[] {
    let opts = {...options, ...defaultCommonOpts(options)};

    if(opts.usePKCE === undefined)
        opts.usePKCE = true;

    if(opts.validCodeChallengeMethods === undefined)
        opts.validCodeChallengeMethods = ['S256', 'plain'];

    if(typeof opts.hashCodeChallenge !== 'function')
        opts.hashCodeChallenge = (code: string, method: string) => codeChallengeHash(method as any, code);

    if(opts.allowCodeChallengeMethodPlain === undefined)
        opts.allowCodeChallengeMethodPlain = false

    if(opts.authorizationCodeLifetime === undefined)
        opts.authorizationCodeLifetime = 60;
    else if (typeof opts.authorizationCodeLifetime !== 'number'
        || opts.authorizationCodeLifetime <= 0
        || Math.trunc(opts.authorizationCodeLifetime) !== opts.authorizationCodeLifetime)
        throw new Error('authorizationCodeLifetime is not positive integer.');

    if(typeof opts.saveAuthorizationCode !== 'function')
        throw new Error('saveAuthorizationCode is not a function');

    if(typeof opts.getAuthorizationCode !== 'function')
        throw new Error('getAuthorizationCode is not a function');

    if(typeof opts.deleteAuthorizationCode !== 'function')
        throw new Error('deleteAuthorizationCode is not a function');

    if(typeof opts.getIDTokenContent !== 'function')
        opts.getIDTokenContent = (user: any) => null;

    return [
        {
            name: 'authorization-code',
            endpoint: 'authorize',
            matchType: 'code',
            function: async (data, callback, eventEmitter) => {
                let {client_id, redirect_uri, code_challenge, code_challenge_method} = data.req.query;

                // Check for PKCE
                if (opts.usePKCE) {
                    if (!code_challenge) {
                        eventEmitter.emit(Events.AUTHORIZATION_FLOWS_CODE_PKCE_INVALID, data.req);
                        return callback(undefined, {
                            error: 'invalid_request',
                            error_description: 'Query parameter code_challenge is missing',
                        });
                    }
                    if (!code_challenge_method) {
                        eventEmitter.emit(Events.AUTHORIZATION_FLOWS_CODE_PKCE_INVALID, data.req);
                        return callback(undefined, {
                            error: 'invalid_request',
                            error_description: 'Query parameter code_challenge_method is missing',
                        });
                    }
                    if (!opts.validCodeChallengeMethods.includes(code_challenge_method)) {
                        eventEmitter.emit(Events.AUTHORIZATION_FLOWS_CODE_PKCE_INVALID, data.req);
                        return callback(undefined, {
                            error: 'invalid_request',
                            error_description: 'Code challenge method is not valid',
                        });
                    }
                }

                // Generate authorization code
                let payload = {client_id, user: data.user};
                let code = signToken(payload, data.serverOpts.secret, opts.authorizationCodeLifetime);

                // Save authorization code to database
                let dbRes = await opts.saveAuthorizationCode({
                    authorizationCode: code,
                    expiresAt: Math.trunc((Date.now() + opts.authorizationCodeLifetime * 1000) / 1000),
                    clientId: client_id,
                    scopes: data.scopes!,
                    user: data.user!,
                    redirectUri: redirect_uri,
                    codeChallenge: code_challenge,
                    codeChallengeMethod: code_challenge_method
                });

                if(!dbRes) {
                    eventEmitter.emit(Events.AUTHORIZATION_FLOWS_CODE_SAVE_ERROR, data.req);
                    return callback(undefined, {
                        error: 'server_error',
                        error_description: 'Encountered an unexpected error',
                    });
                }

                // Respond with authorization code
                callback({code});
            }
        },
        {
            name: 'authorization-code',
            endpoint: 'token',
            matchType: 'authorization_code',
            function: async (data, callback, eventEmitter) => {
                let {client_id, client_secret} = (data.serverOpts.getClientCredentials as any)(data.req);
                let {code, redirect_uri, code_verifier} = data.req.body;
                // if (!client_id) client_id = req.body.client_id;

                if (!code)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Body parameter code is missing'
                    });

                if (!redirect_uri)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Body parameter redirect_uri is missing'
                    });

                if (opts.usePKCE && !code_verifier)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Body parameter code_verifier is missing'
                    });

                // Token verification
                let authCodePayload: any = verifyToken(code, data.serverOpts.secret);
                if (!authCodePayload) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_AUTHORIZATION_CODE_TOKEN_JWT_INVALID, data.req);
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: 'The authorization code has expired'
                    })
                }

                // Payload verification
                if (authCodePayload.client_id !== client_id) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_AUTHORIZATION_CODE_TOKEN_CLIENT_INVALID, data.req);
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: `This authorization code does not belong to client ${client_id}`
                    });
                }

                // Client validation
                if (!(await opts.validateClient(client_id, client_secret))) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_AUTHORIZATION_CODE_CLIENT_INVALID, data.req);
                    return callback(undefined, {
                        error: 'unauthorized_client',
                        error_description: 'Client authentication failed'
                    });
                }

                // Database verification
                let dbCode = await opts.getAuthorizationCode({
                    clientId: client_id,
                    authorizationCode: code,
                    user: authCodePayload.user
                });

                if (!dbCode || dbCode.authorizationCode !== code) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_AUTHORIZATION_CODE_TOKEN_DB_INVALID, data.req);
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: 'The authorization code has expired'
                    });
                }

                // Check if redirect uri is the same that was generated on authorization code
                if (redirect_uri !== dbCode.redirectUri) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_AUTHORIZATION_CODE_REDIRECT_URI_INVALID, data.req);
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: 'Redirect URI does not match the one that was used during authorization'
                    });
                }

                // Check PKCE
                if (opts.usePKCE) {
                    if((await opts.hashCodeChallenge(code_verifier, dbCode.codeChallengeMethod)) !== dbCode.codeChallenge) {
                        eventEmitter.emit(Events.TOKEN_FLOWS_AUTHORIZATION_CODE_PKCE_INVALID, data.req);
                        return callback(undefined, {
                            error: 'invalid_grant',
                            error_description: 'Client failed PKCE verification'
                        });
                    }
                }

                // Database delete
                await opts.deleteAuthorizationCode({
                    clientId: client_id,
                    authorizationCode: code,
                    user: dbCode.user
                });

                // Generate access & refresh tokens
                let tokens = generateARTokens({
                    user: dbCode.user
                }, client_id, dbCode.scopes, data.serverOpts, data.issueRefreshToken);

                // Database save
                let dbRes = await data.serverOpts.saveTokens({
                    accessToken: tokens.access_token,
                    accessTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.accessTokenLifetime!, 'access'),
                    refreshToken: tokens.refresh_token,
                    refreshTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.refreshTokenLifetime!, 'refresh'),
                    clientId: client_id,
                    user: dbCode.user,
                    scopes: dbCode.scopes,
                });

                if(!dbRes) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_AUTHORIZATION_CODE_SAVE_ERROR, data.req);
                    return callback(undefined, {
                        error: 'server_error',
                        error_description: 'Encountered an unexpected error'
                    });
                }

                // Respond with tokens
                callback(tokens);
            }
        }
    ]
}