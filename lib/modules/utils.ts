import * as crypto from "crypto";
import {OAuth2Error} from "../components/types";

/**
 * Will create a query string from an object.
 * @param params
 */
export function buildQuery(params: { [key: string]: string | undefined }): string {
    return Object.keys(params).map(k => params[k] ? `${k}=${params[k]}` : undefined).filter(s => s != undefined).join('&');
}

/**
 * Will generate the code_challenge from the code verifier and code challenge method.
 * @param method The code challenge method.
 * @param verifier The code verifier.
 */
export function codeChallengeHash(method: 'plain' | 'S256' | undefined, verifier: string): string {
    let code = verifier;
    if (method === 'S256') {
        // Hash
        code = crypto.createHash('sha256').update(code).digest('base64');

        // Encode base64 url
        code = code.replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }
    return code;
}

/**
 * Will generate a random string.
 * @param length The length of the string.
 */
export function randStr(length: number): string {
    const chars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890";
    const randomArray = Array.from({ length: length },
        (v, k) => chars[Math.floor(Math.random() * chars.length)]
    );
    return randomArray.join("");
}

/**
 * Will build and send the error response.
 * If a redirect uri is provided, the response will be redirected.
 * @param res
 * @param data
 */
export function error(res: any, data: OAuth2Error & { redirect_uri?: string; state?: string; status?: number; noCache?: boolean }) {
    let wwwAuthHeader = `Bearer error="${data.error}"`;
    if (data.error_description) wwwAuthHeader += ` error_description="${data.error_description}"`;
    if (data.error_uri) wwwAuthHeader += ` error_uri="${data.error_uri}"`;

    let resp: any = {
        error: data.error,
        error_description: data.error_description,
        error_uri: data.error_uri,
    };

    if(data.state != undefined)
        resp.state = data.state;

    if(data.noCache == undefined || data.noCache)
        res.header('Cache-Control', 'no-store')

    res.header('WWW-Authenticate', wwwAuthHeader)

    if (data.redirect_uri)
        res.redirect(`${data.redirect_uri}?${buildQuery(resp)}`);
    else
        res.status(data.status || 400).json(resp)
}