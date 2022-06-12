import * as jwt from "jsonwebtoken";
import {ARTokens} from "../components/types";
import {AuthorizationServerOptions} from "../components/options/authorizationServerOptions";
import {randStr} from "./utils";

/**
 * This function will generate a new JSON Web Token.
 * @param payload The payload that will be included inside the JWT.
 * @param secret The secret that will sign the token.
 * @param expiresIn The expiration time in seconds.
 * @return {string} The token.
 */
export function signToken(payload: object, secret: string, expiresIn?: number): string {
    return jwt.sign({
        random: randStr(8),
        date: Math.floor(Date.now() / 1000),
        payload
    }, secret, {
        expiresIn,
    });
}

/**
 * This function will verify if string is a valid JWT that was generated
 * from the same secret.
 * @param token The string that will be verified.
 * @param secret The secret that used when signing the token.
 * @return {object} The payload inside the JWT.
 */
export function verifyToken(token: string, secret: string): object | null {
    try {
        let payload = jwt.verify(token, secret) as any;
        let contents = payload.payload;

        delete payload.payload
        delete payload.random;
        delete payload.date;

        return {...contents, ...payload};
    } catch (e) {
        return null;
    }
}

/**
 * Will generate the access and refresh tokens and generate the response for the client.
 * @param payload The data that will be included inside the tokens
 * @param client_id The client's id that the tokens belongs to (will be included to the payload).
 * @param scopes The requested scopes (will be included to the payload).
 * @param opts The server's options
 * @param issueRefreshToken Whether to issue a refresh token. This will be take effect only if accessTokenLifetime is not null.
 * @return {object} The client's response which contains the generated tokens.
 */
export function generateARTokens(payload: object, client_id: string, scopes: string[], opts: AuthorizationServerOptions, issueRefreshToken: boolean): ARTokens {
    let accessTokenPayload = {
        ...payload,
        type: 'access_token',
        client_id,
        scopes
    };
    let refreshTokenPayload = {
        ...payload,
        type: 'refresh_token',
        client_id,
        scopes
    };

    let accessToken: string = signToken(accessTokenPayload, opts.secret, opts.accessTokenLifetime ?? undefined);
    let refreshToken: string | undefined;

    // Allow when asked && grant type is available && accessToken does not expire
    if (issueRefreshToken && opts.accessTokenLifetime != null)
        refreshToken = signToken(refreshTokenPayload, opts.secret, opts.refreshTokenLifetime ?? undefined);

    let result: any = {
        access_token: accessToken,
        token_type: 'Bearer',
        refresh_token: refreshToken,
        scope: scopes.join(opts.scopeDelimiter)
    };

    if(opts.accessTokenLifetime != null)
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
    if((type == 'access' && tokens.expires_in) || (type === 'refresh' && tokens.refresh_token))
        return Math.floor((Date.now() + lifetime * 1000) / 1000);
}