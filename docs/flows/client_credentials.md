# Client credentials

The Client Credentials grant is used when applications request an access token to access their
own resources, not on behalf of a user.

## How to use
```javascript
import {clientCredentials} from "oauth2";

authServer.use(clientCredentials({/* options */}));
```

## Options

### `errorUri`
It will override the [`errorUri`](../authorizationServer/authorization_server.md#erroruri)
set at the
[`AuthorizationServer`](../authorizationServer/authorization_server.md) options.