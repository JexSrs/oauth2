import isbot from "isbot";

/**
 * Will check was made from a bot.
 * @param useragent
 */
function isBot(useragent: string): boolean {
    return isbot(useragent);
}

const webviewRegExp = new RegExp('(' + [
    // if it says it's a webview, let's go with that
    'WebView',
    // iOS webview will be the same as safari but missing "Safari"
    '(iPhone|iPod|iPad)(?!.*Safari)',
    // Android Lollipop and Above: webview will be the same as native but it will contain "wv"
    // Android KitKat to lollipop webview will put {version}.0.0.0
    'Android.*(wv|.0.0.0)',
    // old chrome android webview agent
    'Linux; U; Android'
].join('|') + ')', 'ig');

/**
 * Will check if the request was made from an embedded web view.
 * @param useragent
 */
function isEmbeddedWebView(useragent: string): boolean {
    return !!useragent.match(webviewRegExp)
}

/**
 * Will make the appropriate user agent checks.
 * @param useragent
 */
export function validateUserAgent(useragent: string): boolean {
    return !isBot(useragent)
        && !isEmbeddedWebView(useragent);
}