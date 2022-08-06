# Security Considerations
The `oauth2` library will try its best to protect you from outside threats, but the problems
does not end there. Leakage of codes and access tokens can happen from the authorization `front-end`
page or the client's side.

## Third-Party Content
When the authorization page of the Authorization Server or the page of the client that the
authorization request was redirected contains third-party content, data like
authorization code, state or potentially access token can be leaked.

For more information about that read
[Section 4.2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.2.1)
and
[Section 4.2.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.2.2)
of OAuth 2.0 Security Best Current Practice.

For countermeasures read
[Section 4.2.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.2.4)
of OAuth 2.0 Security Best Current Practice.

## Impersonating a Resource Server
An attacker may setup his own resource server and trick a client into
sending access tokens to it that are valid for other resource servers.

For more information read
[Section 4.9.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.9.1)
of OAuth 2.0 Security Best Current Practice.

To countermeasure, you can use
[metadata](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.9.1.1.1)
and
[sender-constrained access tokens](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.9.1.1.2),
For more detailed information read
[Section 4.9.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.9.1.1.1)
of OAuth 2.0 Security Best Current Practice

## TLS
Lack of transport-layer security can have a severe impact on the security of the client
and the protected resources it is authorized to access. The use of transport-layer
security is particularly critical when the authorization process is used as a form of
delegated end-user authentication by the client.

For more information read
[Section 3.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.1)
of The OAuth 2.0 Authorization Framework.

## X-Frame-Options
The `X-Frame-Options` HTTP response header can be used to indicate whether a browser should
be allowed to render a page in a `<frame>`, `<iframe>`, `<embed>` or `<object>`.
Sites can use this to avoid click-jacking attacks, by ensuring that their content
is not embedded into other sites.

For more information read
[X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
header at MDN Web Docs and
[Section 5.2.2.6](https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.6)
of OAuth 2.0 Threat Model and Security Considerations.

## Protect Sensitive Data
It is mandatory to protect sensitive data like tokens or client secrets
to a secure storage.

Most multi-user operating systems segregate the personal storage of
different system users. Moreover, most modern smartphone operating
systems even support the storage of application-specific data in
separate areas of file systems and protect the data from access by
other applications.

Another approach is to keep access tokens in memory (although a refresh token must be saved
to a secure storage).

In case of mobile applications ypu should consider also `device lock` options.

For more information read
[Section 5.1.6](https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.6),
[Section 5.3.1](https://datatracker.ietf.org/doc/html/rfc6819#section-5.3.1),
[Section 5.3.3](https://datatracker.ietf.org/doc/html/rfc6819#section-5.3.3),
[Section 5.3.4](https://datatracker.ietf.org/doc/html/rfc6819#section-5.3.4),
of OAuth 2.0 Threat Model and Security Considerations.

## Access Token Lifetime
By reducing the expiration time of an access token you can protect
against replay, token leak or online guessing.

For more information read
[Section 5.1.5.3](https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.5.3)
of OAuth 2.0 Threat Model and Security Considerations.

## Do not issue refresh tokens
Refresh tokens are long-term credentials, so there is a high chance they may be subject to theft.
If it not necessary do not issue refresh tokens.

For more information read
[Section 5.2.2.1](https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.1)
of OAuth 2.0 Threat Model and Security Considerations.

## Inform the Resource Owner
Always explain to the resource owner (the user) during authorization
which of his resources the client will have access.
This will help the resource owner to understand and not give access
to resources he does not want to.

It is also highly recommended to inform the resource owner
about any authorization requests that he may (or worse may not) authorized.

For more information read
[Section 5.1.3](https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.3),
[Section 5.2.4.2](https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.4.2),
[Section 5.2.4.3](https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.4.3)
of OAuth 2.0 Threat Model and Security Considerations.

## SQL Injection
In cases where the authorization server shares a common database with other apps
not sanitizing external inputs before executing an SQL (or a NOSQL) query will
result in token and secret leakage.

Fo more information read
[Section 5.1.4.1.2](https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.4.1.2)
of OAuth 2.0 Threat Model and Security Considerations.

## No Cleartext Storage of Credentials
The authorization server and the clients should not store credentials in clear text.
Typical approaches are to store hashes instead or to encrypt credentials.

Fo more information read
[Section 5.1.4.1.3](https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.4.1.3),
[Section 5.1.4.1.4](https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.4.1.4)
of OAuth 2.0 Threat Model and Security Considerations.

## Enforce Strong Passwords
OAuth2 may be safe in the aspect of not leaking the resource owner's credentials to
third-party applications, but what happens in case the credentials itself are predictable?
As the authorization server you have to enforce your users to register only strong passwords.

Fo more information read
[Section 5.1.4.2.1](https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.4.2.1)
of OAuth 2.0 Threat Model and Security Considerations.

## Device Authorization Session Spying
While the device is pending authorization, a malicious user may physically spy on the
device user interface and hijack the session by completing the authorization faster
than the user that initiated it.

Fo more information read
[Section 5.5](https://datatracker.ietf.org/doc/html/rfc8628#section-5.5)
of OAuth 2.0 Device Authorization Grant.
