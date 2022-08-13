import * as jwt from "jsonwebtoken";
import {ARTokens} from "../components/types";
import {AuthorizationServerOptions} from "../components/authorizationServerOptions.js";
import {randStr} from "./utils";


export function signToken(data: {
    payload: object;
    secret: string;
    expiresIn?: number,
    audience?: string;
    issuer: string;
}): string {
    for(const key in data.payload) {
        if((<any>data.payload)[key] === undefined)
            delete (<any>data.payload)[key]
    }

    return jwt.sign(data.payload, data.secret, {
        // algorithm: 'RS256',
        // header: {
        //     alg: 'RS256',
        //     typ: 'at+jwt'
        // },
        expiresIn: data.expiresIn,
        audience: data.audience,
        issuer: data.issuer,
        jwtid: randStr(32),
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

export async function generateARTokens(data: {
    req: any;
    payload: object;
    clientId: any;
    scopes: string[] | {
        refresh: string[];
        access: string[];
    };
    opts: AuthorizationServerOptions;
    issueRefreshToken: boolean;
}): Promise<ARTokens> {
    const refreshTokenScopes = Array.isArray(data.scopes) ? data.scopes : data.scopes.refresh;
    const accessTokenScopes = Array.isArray(data.scopes) ? data.scopes : data.scopes.access;

    let audience: string;
    if (typeof data.opts.audience === 'string')
        audience = data.opts.audience;
    else audience = await data.opts.audience!(data.clientId, accessTokenScopes, data.req);

    let accessToken: string = signToken({
        payload: {
            ...data.payload,
            type: 'access_token',
            client_id: data.clientId,
            scopes: accessTokenScopes
        },
        secret: data.opts.secret,
        expiresIn: data.opts.accessTokenLifetime ?? undefined,
        audience,
        issuer: data.opts.baseUrl
    });
    let refreshToken: string | undefined;

    // Allow when asked && grant type is available && accessToken does not expire
    if (data.issueRefreshToken && data.opts.accessTokenLifetime != null)
        refreshToken = signToken({
            payload: {
                ...data.payload,
                type: 'refresh_token',
                client_id: data.clientId,
                scopes: refreshTokenScopes
            },
            secret: data.opts.secret,
            expiresIn: data.opts.refreshTokenLifetime ?? undefined,
            audience,
            issuer: data.opts.baseUrl
        });

    let result: any = {
        access_token: accessToken,
        token_type: 'Bearer',
        refresh_token: refreshToken,
        scope: refreshTokenScopes.join(data.opts.scopeDelimiter)
    };

    if (data.opts.accessTokenLifetime != null)
        result['expires_in'] = data.opts.accessTokenLifetime;

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