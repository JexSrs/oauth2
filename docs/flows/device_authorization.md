### Device Authorization
The OAuth 2.0 Device Authorization Grant (formerly known as the Device Flow) is an OAuth 2.0 extension
that enables devices with no browser or limited input capability to obtain an access token.
This is commonly seen on Apple TV apps, or devices like hardware encoders that can stream video
to a YouTube channel.

## How to use
```javascript
import {deviceFlow} from "oauth2";

authServer.use(deviceFlow({/* options */}));
```


## The two stages
The `evice Authorization` flow has two parts the device code creation (stage 1)
and the token request flow (stage 2).

The first stage is accessed from the
[`deviceAuthorization`](../authorizationServer/functions_and_endpoints.md#device-authorization)
endpoint and generates the `device code` for the client and the `user code`.

The second is accessed from the
[`token`](../authorizationServer/functions_and_endpoints.md#token)
endpoint where it verifies the if the user has used the `user code`
and authorized the client to generate the tokens.

## Options

### `interval`
The minimum amount of seconds that the client should wait between the polling requests to
the token endpoint. It defaults to `5 sec`.

In case the client did not take into account the interval the token endpoint will
respond with the `slow_down` error.

### `expiresIn`
The seconds until the user's code expires.
It defaults to `1800 sec` = 30 minutes.

### `deviceCodeGenerator`
The device code generator. It will override the default generator with a custom one.

This function also supports async calls.
```javascript
deviceCodeGenerator: (client_id, req) => randStr(64);
```

### `userCodeGenerator`
The user code generator. It will override the default generator with a custom one.

This function also supports async calls.
```javascript
deviceCodeGenerator: (client_id, req) => `${randStr(4)}-${randStr(4)}`;
```

It is recommended the code to be small and compact (e.g. `ABCD-1234`) so it can fit in
small screens and the user will not have to type long codes.

### `errorUri`
It will override the [`errorUri`](../authorizationServer/authorization_server.md#erroruri)
set at the
[`AuthorizationServer`](../authorizationServer/authorization_server.md) options.

### `verificationURI`
The url that the user should visit to authorize the client. In this url the
user will have to enter the `user code`. If the user code is valid you should change
the record status from `pending` to `completed`.

It is recommended to be as compact as possible, so it will be able to be fit in small screens.

### `verificationURIComplete`
A verification URI that includes the "user_code" (or
other information with the same function as the "user_code"),
which is designed for non-textual transmission.

The substring `{user-code}` will be replaced in this url with the
generated user code. For example, `https://example.com?userCode={user-code}`
will be transformed to this `https://example.com?userCode=ABCD-EFGH`.

### `saveDevice`
Used at the first stage to save the generated device record with status set as `pending`.
It should always return `true` unless the database did not save the record,
in that case you must return `false`.

It is recommended to save the record in cache (like `redis`) because it will
be requested repeatedly in short time frames.

This function also supports async calls.
```javascript
saveDevice: (data, req) => db.insertDeviceRecord(data);
```

### `getDevice`
Used at the second stage to inquire if a device record exists and if it does
what is its status.

If the status is changed from `pending` to `completed` then the flow will continue
and check if the user authorized the request.

This function also supports async calls.
```javascript
getDevice: (data, req) => db.getDeviceRecord(data);
```

### `removeDevice`
Used at the second stage to ask to delete the device record.
It should always return `true` unless the database did not delete the record,
in that case you must return `false`.

This function also supports async calls.
```javascript
removeDevice: (data, req) => db.removeDeviceRecord(data);
```

### `getUser`
Used at the second stage to inquire if the user authorized the request
and get the user's identification.

If the user declines the request, you have to return null.

This function also supports async calls.
```javascript
getUser: (data, req) => db.getDeviceRecord(data).user_id;
```

### `saveBucket`
Used at the second stage to rate limit the polling requests made by the client.
It should always return `true` unless the database did not save the record,
in that case you must return `false`.

It is recommended to save it in cache (like `redis`) because they will be requested
repeatedly in short time frames.

This function also supports async calls.
```javascript
saveBucket: (deviceCode, bucket, expiresIn, req) => db.saveBucket(deviceCode, bucket);
```

### `getBucket`
Used by the second stage to rate limit the polling requests made by the client.

It will request the bucket that saved before and check if it has expired. If the bucket is not found
(because it has expired), return null.

The bucket is created using a JWT, so even if you provide an expired bucket the flow will still
verify the expiration time.

This function also supports async calls.
```javascript
getBucket: (deviceCode, req) => db.getBucket(deviceCode).bucket;
```
