# Resource owner credentials
The Password grant type is a way to exchange a user's credentials for an access token.
Because the client application has to collect the user's password and send it to the authorization
server, it is not recommended that this grant be used at all anymore.

This flow provides no mechanism for things like multifactor authentication or delegated accounts,
so is quite limiting in practice.

## How to use
```javascript
import {resourceOwnerCredentials} from "oauth2";

authServer.use(resourceOwnerCredentials({/* options */}));
```

As documented in
[OAuth 2.0 Security Best Current Practice - Section 2.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.4),
the resource owner password credentials grant must not be used. This grant type insecurely
exposes the credentials of the resource owner to the client.  Even if the client is benign,
this results in an increased attack surface and users are trained to enter their credentials in
places other than the authorization server.

Furthermore, adapting the resource owner password credentials grant to two-factor authentication,
authentication with cryptographic credentials, and authentication processes that require multiple
steps can be hard or impossible.

## Options

### `errorUri`
It will override the [`errorUri`](../authorizationServer/authorization_server.md#erroruri)
set at the
[`AuthorizationServer`](../authorizationServer/authorization_server.md) options.

### `validateUser`
In resource owner credentials the client takes the user's credentials and sends them
directly to the authorization server.

This function will validate the user's credentials and return the user's identification.
If the credentials are not valid then return null.

The user's identification will be included to the tokens' payloads so:
* Do not include sensitive information, that you don't want others to know.
* The identification must be either a primitive type or valid JSON.
