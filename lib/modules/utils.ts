import * as jwt from "jsonwebtoken";

export function signToken(payload: object, secret: string, expiresIn?: number): string {
    return jwt.sign(payload, secret, {
        algorithm: 'HS512',
        expiresIn
    });
}

export function verifyToken(token: string, secret: string): object {
    return jwt.verify(token, secret) as any;
}