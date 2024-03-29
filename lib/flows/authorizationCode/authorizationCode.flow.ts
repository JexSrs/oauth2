import {Flow} from "../../components/flow";
import {generateARTokens, getTokenExpiresAt, signToken, verifyToken} from "../../utils/token.utils.js";
import {codeChallengeHash} from "../../utils/general.utils.js";
import {AuthorizationCodeOptions} from "./authorizationCode.options.js";
import {Events} from "../../components/events";

export function authorizationCode(opts: AuthorizationCodeOptions): Flow[] {
    const options = Object.assign({}, opts);

    if (options.usePKCE === undefined)
        options.usePKCE = true;

    if (options.validCodeChallengeMethods === undefined)
        options.validCodeChallengeMethods = ['S256'];

    if (typeof options.hashCodeChallenge !== 'function')
        options.hashCodeChallenge = (code: string, method: string) => codeChallengeHash(method as any, code);

    if (options.authorizationCodeLifetime === undefined)
        options.authorizationCodeLifetime = 60;
    else if (options.authorizationCodeLifetime <= 0
        || Math.trunc(options.authorizationCodeLifetime) !== options.authorizationCodeLifetime)
        throw new Error('authorizationCodeLifetime is not positive integer.');

    if (typeof options.saveAuthorizationCode !== 'function')
        throw new Error('saveAuthorizationCode is not a function');

    if (typeof options.getAuthorizationCode !== 'function')
        throw new Error('getAuthorizationCode is not a function');

    if (typeof options.deleteAuthorizationCode !== 'function')
        throw new Error('deleteAuthorizationCode is not a function');

    return [
        {
            name: 'authorization-code',
            endpoint: 'authorize',
            matchType: 'code',
            function: async (data, eventEmitter) => {
                let {redirect_uri, code_challenge, code_challenge_method} = data.req.query;

                // Check for PKCE
                if (options.usePKCE) {
                    if (!code_challenge) {
                        eventEmitter.emit(Events.INVALID_PKCE, data.req);
                        return {
                            error: 'invalid_request',
                            error_description: 'Parameter code_challenge is missing',
                            error_uri: options.errorUri
                        };
                    }

                    if (!code_challenge_method) {
                        eventEmitter.emit(Events.INVALID_PKCE, data.req);
                        return {
                            error: 'invalid_request',
                            error_description: 'Parameter code_challenge_method is missing',
                            error_uri: options.errorUri
                        };
                    }

                    if (!options.validCodeChallengeMethods!.includes(code_challenge_method)) {
                        eventEmitter.emit(Events.INVALID_PKCE, data.req);
                        return {
                            error: 'invalid_request',
                            error_description: 'Code challenge method is not valid',
                            error_uri: options.errorUri
                        };
                    }
                }

                // Generate authorization code
                let payload = {
                    client_id: data.clientId,
                    redirectUri: redirect_uri,
                    scopes: data.scopes!,
                    user: data.user
                };
                let code = signToken({
                    payload,
                    secret: data.serverOpts.secret,
                    expiresIn: options.authorizationCodeLifetime,
                    issuer: data.serverOpts.baseUrl,
                    audience: data.serverOpts.baseUrl,
                    subject: data.user
                });

                // Save authorization code to database
                let dbRes = await options.saveAuthorizationCode({
                    authorizationCode: code,
                    expiresAt: Math.trunc((Date.now() + options.authorizationCodeLifetime! * 1000) / 1000),
                    clientId: data.clientId,
                    user: data.user!,
                    codeChallenge: code_challenge,
                    codeChallengeMethod: code_challenge_method
                }, data.req);

                if (!dbRes) {
                    eventEmitter.emit(Events.FAILED_AUTHORIZATION_CODE_SAVE, data.req);
                    return {
                        error: 'server_error',
                        error_description: 'Encountered an unexpected error',
                        error_uri: options.errorUri
                    };
                }

                // Respond with authorization code
                return {code};
            }
        },
        {
            name: 'authorization-code',
            endpoint: 'token',
            matchType: 'authorization_code',
            function: async (data, eventEmitter) => {
                let {code, redirect_uri, code_verifier} = data.req.body;

                if (!code)
                    return {
                        error: 'invalid_request',
                        error_description: 'Body parameter code is missing',
                        error_uri: options.errorUri
                    };

                if (!redirect_uri)
                    return {
                        error: 'invalid_request',
                        error_description: 'Body parameter redirect_uri is missing',
                        error_uri: options.errorUri
                    };

                if (options.usePKCE && !code_verifier)
                    return {
                        error: 'invalid_request',
                        error_description: 'Body parameter code_verifier is missing',
                        error_uri: options.errorUri
                    };

                // Token verification
                let authCodePayload: any = verifyToken(code, data.serverOpts.secret, data.serverOpts.baseUrl, data.serverOpts.baseUrl);
                if (!authCodePayload) {
                    eventEmitter.emit(Events.INVALID_AUTHORIZATION_CODE_TOKEN_JWT, data.req);
                    return {
                        error: 'invalid_grant',
                        error_description: 'The authorization code has expired',
                        error_uri: options.errorUri
                    };
                }

                // Payload verification
                if (authCodePayload.client_id !== data.clientId) {
                    eventEmitter.emit(Events.INVALID_AUTHORIZATION_CODE_TOKEN_CLIENT, data.req);
                    return {
                        error: 'invalid_grant',
                        error_description: `This authorization code does not belong to client ${data.clientId}`,
                        error_uri: options.errorUri
                    };
                }

                // Database verification
                let dbCode = await options.getAuthorizationCode({
                    clientId: data.clientId,
                    authorizationCode: code,
                    user: authCodePayload.user
                }, data.req);

                if (!dbCode || dbCode.authorizationCode !== code) {
                    eventEmitter.emit(Events.INVALID_AUTHORIZATION_CODE_TOKEN_DB, data.req);
                    return {
                        error: 'invalid_grant',
                        error_description: 'The authorization code has expired',
                        error_uri: options.errorUri
                    };
                }

                // Check if redirect uri is the same that was generated on authorization code
                if (redirect_uri !== authCodePayload.redirectUri) {
                    eventEmitter.emit(Events.INVALID_REDIRECT_URI, data.req);
                    return {
                        error: 'invalid_grant',
                        error_description: 'Redirect URI does not match the one that was used during authorization',
                        error_uri: options.errorUri
                    };
                }

                // Check PKCE
                if (options.usePKCE) {
                    if ((await options.hashCodeChallenge!(code_verifier, dbCode.codeChallengeMethod!, data.req)) !== dbCode.codeChallenge) {
                        eventEmitter.emit(Events.INVALID_PKCE, data.req);
                        return {
                            error: 'invalid_grant',
                            error_description: 'Client failed PKCE verification',
                            error_uri: options.errorUri
                        };
                    }
                }

                // Database delete
                await options.deleteAuthorizationCode({
                    clientId: data.clientId,
                    authorizationCode: code,
                    user: dbCode.user
                }, data.req);

                // Generate access & refresh tokens
                let tokens = await generateARTokens({
                    req: data.req,
                    payload: {},
                    user: dbCode.user,
                    clientId: data.clientId,
                    scopes: authCodePayload.scopes,
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
                    user: dbCode.user,
                    scopes: authCodePayload.scopes,
                }, data.req);

                if (!dbRes) {
                    eventEmitter.emit(Events.FAILED_TOKEN_SAVE, data.req);
                    return {
                        error: 'server_error',
                        error_description: 'Encountered an unexpected error',
                        error_uri: options.errorUri
                    };
                }

                // Respond with tokens
                return tokens;
            }
        }
    ]
}