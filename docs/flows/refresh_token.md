# Refresh token
The Refresh Token grant type is used by clients to exchange a refresh token for an access token when
the access token has expired. This allows clients to continue to have a valid access token without further
interaction with the user.

## How to use
```javascript
import {refreshToken} from "oauth2";

authServer.use(refreshToken({/* options */}));
```

## Options

### `errorUri`
It will override the [`errorUri`](../authorizationServer/authorization_server.md#erroruri)
set at the
[`AuthorizationServer`](../authorizationServer/authorization_server.md) options.
