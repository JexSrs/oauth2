import * as jwt from "jsonwebtoken";
import {ServerOptions} from "../components/serverOptions";
import {ARTokensResponse} from "../components/types";

export function signToken(payload: object, secret: string, expiresIn?: number): string {
    return jwt.sign(payload, secret, {
        algorithm: 'HS512',
        expiresIn
    });
}

export function verifyToken(token: string, secret: string): object | null {
    try {
        return jwt.verify(token, secret) as any;
    } catch (e) {
        return null;
    }
}

export async function generateARTokens(payload: object, req: any, opts: Partial<ServerOptions>, generateRefreshToken: boolean = true): Promise<ARTokensResponse> {
    let accessTokenPayload = {
        ...payload,
        type: 'accessToken'
    };
    let refreshTokenPayload = {
        ...payload,
        type: 'refreshToken'
    };

    let accessToken: string = signToken(accessTokenPayload, opts.secret, opts.accessTokenLifetime ?? undefined);
    let refreshToken: string | undefined;
    if (opts.issueRefreshToken && generateRefreshToken)
        refreshToken = signToken(refreshTokenPayload, opts.secret, opts.refreshTokenLifetime ?? undefined);

    // Database save
    await opts.tokenHandler.saveTokens({
        accessToken,
        accessTokenExpiresAt: Math.trunc((Date.now() + opts.accessTokenLifetime * 1000) / 1000),
        refreshToken,
        refreshTokenExpiresAt: Math.trunc((Date.now() + opts.refreshTokenLifetime * 1000) / 1000),
        clientId: (payload as any).client_id,
        user: (payload as any).user,
        scopes: (payload as any).scopes,
    });

    return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: opts.accessTokenLifetime,
        refresh_token: refreshToken,
    };
}