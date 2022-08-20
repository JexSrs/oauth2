# Authorization code
The Authorization Code grant type is used by confidential and public clients to exchange an authorization
code for an access token. After the user returns to the client via the redirect URL, the application
will get the authorization code from the URL and use it to request an access token.

This library is compatible with passport authorization code flow.
For more information about passport see [Passport.js](https://www.passportjs.org/)
and [passport-oauth2](https://www.passportjs.org/packages/passport-oauth2/).

## How to use
```javascript
import {authorizationCode} from "oauth2";

authServer.use(authorizationCode({/* options */}));
```

## The two stages
The `Authorization Code` flow has two parts the authorization flow (stage 1)
and the token request flow (stage 2).

The first stage is accessed from the
[`authorize`](../authorizationServer/functions_and_endpoints.md#authorize)
endpoint and generates the authorization code

The second is accessed from the
[`token`](../authorizationServer/functions_and_endpoints.md#token)
endpoint where it verifies the authorization code and generates the tokens.

## Options

### `usePKCE`
PKCE (Proof Key for Code Exchange) is an extension to the authorization code flow
that enhances protection. More specifically ts to prevents CSRF and authorization code injection attacks.
It defaults to `true`.

If PKCE is enabled the fields `code_challenge` and `code_challenge_method` must be included in the request.

As documented in
[OAuth 2.0 Security Best Current Practice - Section 2.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.1),
PKCE extension must be used for public clients and should be used by confidential clients as well. 

### `validCodeChallengeMethods`
The code challenge methods the client is allowed to use.
it defaults to `['S256']`.

Note this options takes effect only if PKCE is enabled.

As documented in
[OAuth 2.0 Security Best Current Practice - Section 2.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.1),
clients should use PKCE code challenge methods that do not expose the PKCE verifier in
the authorization request. So the option `plain` is not recommended.

### `hashCodeChallenge`
This function will take the code verifier and hash it using the code challenge method.
It defaults to hashing for the methods `S256` and `plain`.

Note this options takes effect only if PKCE is enabled.

This function also supports async calls.
```javascript
hashCodeChallenge: (code, method, req) => {
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
```

### `authorizationCodeLifetime`
The time in seconds where the authorization code will be valid. It defaults to `60 sec` = 1 minute.

### `errorUri`
It will override the [`errorUri`](../authorizationServer/authorization_server.md#erroruri)
set at the
[`AuthorizationServer`](../authorizationServer/authorization_server.md) options.

### `saveAuthorizationCode`
Used by the first stage to save the generated authorization code to the database.
It should always return `true` unless the database did not save the record,
in that case you must return `false`.

This function also supports async calls.
```javascript
saveAuthorizationCode: (data, req) => db.saveAuthorizationCode(data);
```

Because this is a short-lived code, it is recommended to save it in cache (like `redis`)
and expire it after `authorizationCodeLifetime` seconds.

You must save all the data presented here, because they will be used at the second stage.

### `getAuthorizationCode`
Used by the second stage to inquire if the authorization code is still valid.

This function also supports async calls.
```javascript
getAuthorizationCode: (data, req) => db.getAuthorizationCode(data);
```

### `deleteAuthorizationCode`
It is used by the second stage to ask for the deletion of the authorization code.
It should always return `true` unless the database did not delete the record,
in that case you must return `false`.

This function also supports async calls.
```javascript
deleteAuthorizationCode: (data, req) => db.deleteAuthorizationCode(data);
```

It is extremely important to delete an authorization code after it is used
to avoid being used by someone else.
If the authorization code is used more than once, it is recommended to treat it as an attack (leaked code)
and revoke all the generated tokens.
