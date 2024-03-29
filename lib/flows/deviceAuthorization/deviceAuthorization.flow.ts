import {Flow} from "../../components/flow";
import {generateARTokens, getTokenExpiresAt, signToken, verifyToken} from "../../utils/token.utils.js";
import {DeviceAuthorizationOptions} from "./deviceAuthorization.options.js";
import {error, randStr, userCodeGenerator} from "../../utils/general.utils.js";
import {Events} from "../../components/events";

export function deviceAuthorization(opts: DeviceAuthorizationOptions): Flow[] {
    const options = Object.assign({}, opts);

    if (options.interval === undefined)
        options.interval = 5;

    if (options.expiresIn === undefined)
        options.expiresIn = 5;

    if (options.deviceCodeGenerator === undefined)
        options.deviceCodeGenerator = (client_id, req) => randStr(64);

    if (options.userCodeGenerator === undefined)
        options.userCodeGenerator = (client_id, req) => userCodeGenerator();

    if (options.verificationURI.trim().length === 0)
        throw new Error('verificationURI must be non empty string');

    return [
        {
            name: 'device-authorization',
            endpoint: 'device_authorization',
            matchType: 'token',
            function: async (data, eventEmitter) => {
                const {scope} = data.req.body;

                // Validate scopes
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

                let deviceCode = await options.deviceCodeGenerator!(data.clientId, data.req);
                let userCode = await options.userCodeGenerator!(data.clientId, data.req);

                let dbRes = await options.saveDevice({
                    clientId: data.clientId,
                    deviceCode,
                    userCode,
                    interval: options.interval!,
                    expiresAt: Math.trunc((Date.now() + options.expiresIn! * 1000) / 1000),
                    scopes,
                    status: 'pending'
                }, data.req);

                if (!dbRes) {
                    eventEmitter.emit(Events.FAILED_DEVICE_CODE_SAVE, data.req);
                    return {
                        error: 'server_error',
                        error_description: 'Encountered an unexpected error',
                        error_uri: options.errorUri
                    };
                }

                const response: any = {
                    device_code: deviceCode,
                    user_code: userCode,
                    verification_uri: options.verificationURI,
                    interval: options.interval,
                    expires_in: options.expiresIn
                };

                if(options.verificationURIComplete !== undefined)
                    response.verification_uri_complete = options.verificationURIComplete
                        .replace('{user-code}', userCode);

                return response;
            }
        },
        {
            name: 'device-authorization',
            endpoint: 'token',
            matchType: 'urn:ietf:params:oauth:grant-type:device_code',
            function: async (data, eventEmitter) => {
                let {device_code} = data.req.body;

                if (!device_code)
                    return {
                        error: 'invalid_request',
                        error_description: 'Body parameter device_code is missing',
                        error_uri: options.errorUri
                    };

                // Rate limit using deviceCode
                // We are using jwt tokens to make sure that the bucket is expired,
                // in case the app sends the code even if it has expired.
                const oldBucket = await options.getBucket(device_code, data.req);
                if (oldBucket != null) {
                    const payload = verifyToken(oldBucket, data.serverOpts.secret, data.serverOpts.baseUrl, data.serverOpts.baseUrl);
                    if (payload != null) {
                        eventEmitter.emit(Events.SLOW_DOWN, data.req);
                        return {
                            error: 'slow_down',
                            status: 400,
                            error_uri: options.errorUri
                        };
                    }
                }

                // The signed JWT is internal and will never go to any user or client
                const bucket = signToken({
                    payload: {
                        deviceCode: device_code,
                        clientId: data.clientId
                    },
                    secret: data.serverOpts.secret,
                    expiresIn: options.interval,
                    issuer: data.serverOpts.baseUrl,
                    audience: data.serverOpts.baseUrl,
                    subject: undefined
                });
                await options.saveBucket(device_code, bucket, options.interval!, data.req);

                // Get saved device
                let dbDev = await options.getDevice({
                    deviceCode: device_code,
                    clientId: data.clientId
                }, data.req);

                if (!dbDev || (dbDev.status !== 'pending' && dbDev.status !== 'completed')) {
                    eventEmitter.emit(Events.INVALID_DEVICE_CODE, data.req);
                    return {
                        error: 'invalid_grant',
                        error_description: 'Device code not found',
                        error_uri: options.errorUri,
                        status: 400
                    };
                }

                if (dbDev.expiresAt <= Math.trunc(Date.now() / 1000)) {
                    eventEmitter.emit(Events.EXPIRED_DEVICE_CODE, data.req);
                    return {
                        error: 'expired_token',
                        status: 400,
                        error_uri: options.errorUri
                    };
                }

                if (dbDev.status === 'pending') {
                    eventEmitter.emit(Events.REQUEST_PENDING, data.req);
                    return {
                        error: 'authorization_pending',
                        status: 400,
                        error_uri: options.errorUri
                    };
                }

                // Request completed - Get user if authorized
                let user = await options.getUser(dbDev.deviceCode, dbDev.userCode, data.req);
                if (user == null) {
                    eventEmitter.emit(Events.ACCESS_DENIED, data.req);
                    return {
                        error: 'access_denied',
                        status: 400,
                        error_uri: options.errorUri
                    };
                }

                await options.removeDevice({
                    clientId: data.clientId,
                    deviceCode: device_code
                }, data.req);

                // Generate access & refresh tokens
                let tokens = await generateARTokens({
                    req: data.req,
                    payload: {},
                    user,
                    clientId: data.clientId,
                    scopes: dbDev.scopes,
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
                    scopes: dbDev.scopes,
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
    ];
}