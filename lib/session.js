//==============================================================================
// A middleware wrapper around the express-session module that encapulates the
// initialization of the session options and also handles secure cookies by
// adding the x-forwarded-proto and forwarded headers as these are not provided
// by the Azure web application container.
//
// Usage: app.use(session());
//
//==============================================================================
// Copyright (c) 2016 Frank Hellwig
//==============================================================================

'use strict';

//------------------------------------------------------------------------------
// Dependencies
//------------------------------------------------------------------------------

const fileStore = require('session-file-store');
const pkgfinder = require('pkgfinder');
const session = require('express-session');

//------------------------------------------------------------------------------
// Initialization
//------------------------------------------------------------------------------

const pkg = pkgfinder();

//------------------------------------------------------------------------------
// Exports
//------------------------------------------------------------------------------

module.exports = function(app, options) {

    const FileStore = fileStore(session);

    // Override the touch method because we don't want the session touched on
    // every request, only when the access token is refreshed. When the token
    // is refreshed, the session will have changed, which triggers a save.
    FileStore.prototype.touch = function(sid, session, callback) {
        callback(null);
    }

    const path = pkg.resolve(options.sessionStorageDirectory);

    const store = new FileStore({
        path: path
    });

    const sessionOptions = {
        cookie: {
            secure: options.sessionCookieSecure,
            httpOnly: true,
            maxAge: options.sessionExpiresSeconds * 1000
        },
        name: options.sessionCookieName,
        proxy: options.sessionCookieSecure,
        resave: false,
        saveUninitialized: false,
        secret: options.sessionCookieSecret,
        store: store
    };

    const sessionFn = session(sessionOptions);

    app.use((req, res, next) => {
        if (options.sessionCookieSecure) {
            req.headers['x-forwarded-proto'] = 'https';
            req.headers['forwarded'] = 'proto=https'; // RFC 7239
        }
        req.sessionCookieName = options.sessionCookieName;
        sessionFn(req, res, next);
    });
};
