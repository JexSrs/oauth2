import * as jwt from "jsonwebtoken";
import {ARTokens} from "../components/types";
import {AuthorizationServerOptions} from "../components/options/authorizationServerOptions";
import {randStr} from "./utils";

export function signToken(payload: object, secret: string, expiresIn?: number): string {
    return jwt.sign({
        random: randStr(64),
        payload
    }, secret, {
        expiresIn,
    });
}

export function verifyToken(token: string, secret: string): object | null {
    try {
        let payload = jwt.verify(token, secret) as any;
        let contents = payload.payload;
        delete payload.payload
        delete payload.random;
        return {...contents, ...payload};
    } catch (e) {
        return null;
    }
}

export async function generateARTokens(payload: object, client_id: string, scopes: string[], opts: AuthorizationServerOptions, issueRefreshToken: boolean): Promise<ARTokens> {
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

    let expires_in = undefined;
    if(opts.accessTokenLifetime != null)
        expires_in = opts.accessTokenLifetime;

    return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in,
        refresh_token: refreshToken,
        scope: scopes.join(opts.scopeDelimiter)
    };
}

export function getTokenExpiresAt(tokens: ARTokens, lifetime: number, type: 'access' | 'refresh'): number | undefined {
    if((type == 'access' && tokens.expires_in) || (type === 'refresh' && tokens.refresh_token))
        return Math.floor((Date.now() + lifetime * 1000) / 1000);
}