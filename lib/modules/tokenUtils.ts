import * as jwt from "jsonwebtoken";
import {AuthorizationServerOptions} from "../components/authorizationServerOptions";
import {ARTokensResponse, OAuth2Error} from "../components/types";
import {AuthorizeErrorRequest} from "../components/authorizeErrorRequest";
import {GrantTypes} from "../components/GrantTypes";

export function signToken(payload: object, secret: string, issuer: string, expiresIn?: number): string {
    return jwt.sign(payload, secret, {
        algorithm: 'HS512',
        expiresIn,
        issuer,
        audience: 'api://default'
    });
}

export function verifyToken(token: string, secret: string, issuer: string): object | null {
    try {
        return jwt.verify(token, secret, {
            algorithms: ['HS512'],
            issuer,
        }) as any;
    } catch (e) {
        return null;
    }
}

export async function generateARTokens(payload: object, req: any, opts: Partial<AuthorizationServerOptions>, generateRefreshToken: boolean = true): Promise<ARTokensResponse | OAuth2Error> {
    let accessTokenPayload = {
        ...payload,
        type: 'accessToken'
    };
    let refreshTokenPayload = {
        ...payload,
        type: 'refreshToken'
    };

    let accessToken: string = signToken(accessTokenPayload, opts.secret, opts.issuer, opts.accessTokenLifetime ?? undefined);
    let refreshToken: string | undefined;

    // Allow when asked && grant type is available && accessToken does not expire
    if (generateRefreshToken
        && opts.grantTypes.includes(GrantTypes.REFRESH_TOKEN)
        && opts.accessTokenLifetime != null)
        refreshToken = signToken(refreshTokenPayload, opts.secret, opts.issuer, opts.refreshTokenLifetime ?? undefined);

    // Database save
    let dbRes = await opts.tokenHandler.saveTokens({
        accessToken,
        accessTokenExpiresAt: Math.trunc((Date.now() + opts.accessTokenLifetime * 1000) / 1000),
        refreshToken,
        refreshTokenExpiresAt: Math.trunc((Date.now() + opts.refreshTokenLifetime * 1000) / 1000),
        clientId: (payload as any).client_id,
        user: (payload as any).user,
        scopes: (payload as any).scopes,
    });
    if(!dbRes) return {
        error: AuthorizeErrorRequest.SERVER_ERROR,
        error_description: 'Encountered an unexpected database error'
    };

    return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: opts.accessTokenLifetime,
        refresh_token: refreshToken,
        scope: (payload as any).scopes.join(opts.scopeDelimiter)
    };
}