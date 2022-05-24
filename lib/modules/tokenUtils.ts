import * as jwt from "jsonwebtoken";
import {ARTokens} from "../components/types";
import {AuthorizationServerOptions} from "../components/options/authorizationServerOptions";

export function signToken(payload: object, secret: string, expiresIn?: number): string {
    return jwt.sign(payload, secret, {
        algorithm: 'HS512',
        expiresIn,
    });
}

export function verifyToken(token: string, secret: string): object | null {
    try {
        return jwt.verify(token, secret) as any;
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

    return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: opts.accessTokenLifetime != null ? opts.accessTokenLifetime : undefined,
        refresh_token: refreshToken,
        scope: scopes.join(opts.scopeDelimiter)
    };
}