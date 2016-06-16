# adal-express

Active Directory Authentication Library (ADAL) for Express

## Usage

```javascript
const adal = require('adal-express');

...

adal(app, options);
```

## Options

```javascript
options =  {
    serverPortNumber: 443,
    azureTenantId: 'my-company.com',
    azureClientId: "8b3ecd7f-d585-4d36-94c9-3ac1d60992fd",
    azureClientSecret: "etTGallILSzAjePe4gw8v9RSb22tJASS3GnKlDw31R4=",
    azureResourceUri: "https://my-backend-api.my-company.com",
    localApiPath: "/api",
    remoteApiUri: "https://my-backend-api.my-company.com/api",
    sessionCookieName: "my-app.sid",
    sessionCookieSecret: "ac0ac8d3c699538ffe0994544d318f8cf8f7d7e0",
    sessionCookieSecure: true,
    sessionExpiresSeconds: 864000,
    sessionStorageDirectory: "sessions"
};
```

## Login

Issue a GET request to /.auth/login. You must provide the `post_login_redirect_uri` query parameter and this must be an absolute URI.

## Logout

Issue a GET request to /.auth/logout. You must provide the `post_logout_redirect_uri` query parameter and this must be an absolute URI.
