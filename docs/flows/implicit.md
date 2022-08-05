# Implicit
The Implicit flow was a simplified OAuth flow previously recommended for native apps and JavaScript
apps where the access token was returned immediately without an extra authorization code exchange step.

## How to use
```javascript
import {implicit} from "oauth2";

authServer.use(implicit({/* options */}));
```

As documented in
[OAuth 2.0 Security Best Current Practice - Section 2.1.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.2),
the implicit grant and other response types causing the authorization server to issue
access tokens in the authorization response are vulnerable to access token leakage and
access token replay.

Public clients such as native apps and JavaScript apps should now use the
[`Authorization Code`](./authorization_code.md)
flow with the `PKCE` extension instead.

## Options

### `errorUri`
It will override the [`errorUri`](../authorizationServer/authorization_server.md#erroruri)
set at the
[`AuthorizationServer`](../authorizationServer/authorization_server.md) options.
