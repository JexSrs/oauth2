import * as jwt from "jsonwebtoken";
import {ARTokens} from "../components/types";
import {AuthorizationServerOptions} from "../components/authorizationServerOptions.js";
import {randStr} from "./utils";

/**
 * This function will generate a new JSON Web Token.
 * @param payload The payload that will be included inside the JWT.
 * @param secret The secret that will sign the token.
 * @param expiresIn The expiration time in seconds.
 * @param audience
 * @param issuer
 * @return {string} The token.
 */
export function signToken(payload: object, secret: string, expiresIn: number | undefined, audience: string, issuer: string): string {
    return jwt.sign(payload, secret, {
        expiresIn,
        audience,
        issuer,
        jwtid: randStr(32)
    });
}

/**
 * This function will verify if string is a valid JWT that was generated
 * from the same secret.
 * @param token The string that will be verified.
 * @param secret The secret that used when signing the token.
 * @param audience
 * @param issuer
 * @return {object} The payload inside the JWT.
 */
export function verifyToken(token: string, secret: string, audience: string | undefined, issuer: string): object | null {
    try {
        return jwt.verify(token, secret, {
            audience,
            issuer,
            clockTolerance: 0,
        }) as any;
    } catch (e) {
        return null;
    }
}

/**
 * Will generate the access and refresh tokens and generate the response for the client.
 * @param req
 * @param payload The data that will be included inside the tokens
 * @param client_id The client's id that the tokens belongs to (will be included to the payload).
 * @param scopes The requested scopes (will be included to the payload).
 * @param opts The server's options
 * @param issueRefreshToken Whether to issue a refresh token. This will be take effect only if accessTokenLifetime is not null.
 * @return {object} The client's response which contains the generated tokens.
 */
export async function generateARTokens(
    req: any,
    payload: object,
    client_id: any,
    scopes: string[] | {refresh: string[], access: string[]},
    opts: AuthorizationServerOptions,
    issueRefreshToken: boolean
): Promise<ARTokens> {
    const refreshTokenScopes = Array.isArray(scopes) ? scopes : scopes.refresh;
    const accessTokenScopes = Array.isArray(scopes) ? scopes : scopes.access;

    let accessTokenPayload = {
        ...payload,
        type: 'access_token',
        client_id,
        scopes: accessTokenScopes
    };
    let refreshTokenPayload = {
        ...payload,
        type: 'refresh_token',
        client_id,
        scopes: refreshTokenScopes
    };

    let audience: string;
    if (typeof opts.audience === 'string')
        audience = opts.audience;
    else audience = await opts.audience!(client_id, req);

    let accessToken: string = signToken(accessTokenPayload, opts.secret, opts.accessTokenLifetime ?? undefined, audience, opts.issuer);
    let refreshToken: string | undefined;

    // Allow when asked && grant type is available && accessToken does not expire
    if (issueRefreshToken && opts.accessTokenLifetime != null)
        refreshToken = signToken(refreshTokenPayload, opts.secret, opts.refreshTokenLifetime ?? undefined, audience, opts.issuer);

    let result: any = {
        access_token: accessToken,
        token_type: 'Bearer',
        refresh_token: refreshToken,
        scope: refreshTokenScopes.join(opts.scopeDelimiter)
    };

    if (opts.accessTokenLifetime != null)
        result['expires_in'] = opts.accessTokenLifetime;

    return result;
}

/**
 * Will return the expiration date in seconds since EPOCH for a token.
 * @param tokens The tokens that was generated.
 * @param lifetime The lifetime of the token.
 * @param type The type of the token (access or refresh).
 */
export function getTokenExpiresAt(tokens: ARTokens, lifetime: number, type: 'access' | 'refresh'): number | undefined {
    if ((type == 'access' && tokens.expires_in) || (type === 'refresh' && tokens.refresh_token))
        return Math.floor((Date.now() + lifetime * 1000) / 1000);
}