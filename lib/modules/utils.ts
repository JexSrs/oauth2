import * as crypto from "crypto";
import {OAuth2Error} from "../components/types";

export function buildRedirectURI(redirectURI: string, params: { [key: string]: string | undefined }): string {
    let r = `${redirectURI}?`;
    for (const key in params) {
        if(params[key] !== undefined)
            r += `${key}=${params[key]}&`;
    }

    return r.substring(0, r.length - 1);
}

export function codeChallengeHash(challenge: 'plain' | 'S256' | undefined, str: string): string {
    let code = str;
    if (challenge === 'S256') {
        // Hash
        code = crypto.createHash('sha256').update(code).digest('base64');

        // Encode base64 url
        code = code.replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }
    return code;
}

export function isEmbeddedWebView(req: any): boolean {
    // TODO - embedded web view
    //      - https://stackoverflow.com/questions/37591279/detect-if-user-is-using-webview-for-android-ios-or-a-regular-browser
    return false;
}

export function defaultCommonOpts(options: any) {
    let opts = options || {};

    if(typeof opts.validateClient !== 'function')
        throw new Error('validateClient is not a function');

    return opts;
}

export function randStr(length: number): string {
    const chars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890";
    const randomArray = Array.from({ length: length },
        (v, k) => chars[Math.floor(Math.random() * chars.length)]
    );
    return randomArray.join("");
}

export function error(res: any, data: OAuth2Error & { redirect_uri?: string; state?: string; status?: number; cache?: boolean }) {
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

    if(!data.cache)
        res.header('Cache-Control', 'no-store')

    res.header('WWW-Authenticate', wwwAuthHeader)

    if (data.redirect_uri)
        res.redirect(buildRedirectURI(data.redirect_uri, resp));
    else
        res.status(data.status || 400).json(resp)
}

