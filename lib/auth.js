//==============================================================================
// node-adal: Node.js Active Directory authorization Libary.
// Provides the user authorization middleware. The middleware provides three
// public endpoints and one for internal use as the redirect URI required by
// the OAuth2 protocol for the authorization code grant flow.
//
// Usage: auth(app, options);
//
// Endpoint: /.auth/login  - Starts the OAuth2 login flow.
// Endpoint: /.auth/reply  - [Internal Use] The authorization code reply URI.
// Endpoint: /.auth/claims - Returns the user claims from the access token.
// Endpoint: /.auth/logout - Signs the user out and deletes the session.
//
//==============================================================================
// Copyright (c) 2016 Frank Hellwig
//==============================================================================

'use strict';

//------------------------------------------------------------------------------
// Dependencies
//------------------------------------------------------------------------------

const qs = require('querystring');
const HttpsService = require('https-service');
const HttpsError = require('https-error');
const token = require('./token');

//------------------------------------------------------------------------------
// Initialization
//------------------------------------------------------------------------------

const POST_LOGIN_REDIRECT_URI = 'post_login_redirect_uri';
const POST_LOGOUT_REDIRECT_URI = 'post_logout_redirect_uri';

const EQUERY = "EQUERY: The '%s' is a required query parameter.";
const EABSURI = "EABSURI: The '%s' must be an absolute URI.";
const ESESSION = "ESESSION: The '%s' is a required session value.";
const EINVAL = "EINVAL: The '%s' is invalid.";

const FIVE_MINUTES = 5 * 60 * 1000;
const AAD_HOSTNAME = 'login.microsoftonline.com';

const _aadService = new HttpsService(AAD_HOSTNAME);

//------------------------------------------------------------------------------
// Exports
//------------------------------------------------------------------------------

module.exports = authMiddleware;

//------------------------------------------------------------------------------
// Public
//------------------------------------------------------------------------------

function authMiddleware(app, options) {

    app.get('/.auth/login', login);
    app.get('/.auth/reply', reply);
    app.get('/.auth/claims', claims);
    app.get('/.auth/logout', logout);

    function login(req, res, next) {
        let postLoginRedirectUri = req.query[POST_LOGIN_REDIRECT_URI];
        if (!postLoginRedirectUri) {
            next(HttpsError.badRequest(EQUERY, POST_LOGIN_REDIRECT_URI));
        } else if (!_isAbsolute(postLoginRedirectUri)) {
            next(HttpsError.badRequest(EABSURI, POST_LOGIN_REDIRECT_URI));
        } else {
            req.session.POST_LOGIN_REDIRECT_URI = postLoginRedirectUri;
            req.session.save(err => {
                res.redirect(_makeLoginUri(req));
            });
        }
    }

    // Receives the authorization code and requests the access and refresh tokens.
    // The state parameter is compared to the session ID to detect CSRF attacks.
    function reply(req, res, next) {
        let error = req.query.error;
        if (error) return next(error);

        let code = req.query.code;
        if (!code) return next(HttpsError.badRequest(EQUERY, 'code'));

        let state = req.query.state;
        if (!state) return next(HttpsError.badRequest(EQUERY, 'state'));
        if (state !== req.sessionID) return next(HttpsError.badRequest(EINVAL, 'state'));

        let redirectUri = req.session.POST_LOGIN_REDIRECT_URI;
        if (!redirectUri) return next(HttpsError.badRequest(ESESSION, POST_LOGIN_REDIRECT_URI));
        delete req.session.POST_LOGIN_REDIRECT_URI;

        token.getToken(options, code, _makeReplyUri(req), (err, response) => {
            if (err) return next(err);
            Object.assign(req.session, response);
            req.session.save(err => {
                res.redirect(redirectUri);
            });
        });
    }

    function claims(req, res, next) {
        let userClaims = req.session.userClaims;
        if (userClaims) {
            res.json(userClaims);
        } else {
            res.status(204).end();
        }
    }

    function logout(req, res, next) {
        let redirectUri = req.query[POST_LOGOUT_REDIRECT_URI];
        if (!redirectUri) {
            next(HttpsError.badRequest(EQUERY, POST_LOGOUT_REDIRECT_URI));
        } else if (!_isAbsolute(redirectUri)) {
            next(HttpsError.badRequest(EABSURI, POST_LOGOUT_REDIRECT_URI));
        } else {
            req.session.destroy(err => {
                res.clearCookie(req.sessionCookieName);
                res.redirect(_makeLogoutUri(redirectUri));
            });
        }
    }

    //--------------------------------------------------------------------------
    // Private
    //--------------------------------------------------------------------------

    // Creates a URI for the specified endpoint.
    // The endpoint parameter is the last part of the URI (e.g., "authorize").
    function _endpointUri(endpoint) {
        let buf = [];
        buf.push('https://');
        buf.push(AAD_HOSTNAME);
        buf.push('/');
        buf.push(options.azureTenantId);
        buf.push('/oauth2/');
        buf.push(endpoint);
        return buf.join('');
    }

    // Returns true if the specified URI contains '://'.
    function _isAbsolute(uri) {
        return uri.indexOf('://') >= 0;
    }

    function _makeLoginUri(req) {
        let query = {
            state: req.sessionID,
            client_id: options.azureClientId,
            domain_hint: options.azureTenantId,
            //login_hint: 'you@' + options.azureTenantId,
            prompt: 'login',
            redirect_uri: _makeReplyUri(req),
            resource: options.azureResourceUri,
            response_type: 'code'
        };
        return _endpointUri('authorize') + '?' + qs.stringify(query);
    }

    function _makeReplyUri(req) {
        const buf = [];
        const host = req.get('host'); // includes port
        if (host.startsWith('localhost')) {
            buf.push('http://');
        } else {
            buf.push('https://');
        }
        buf.push(host);
        buf.push('/.auth/reply');
        return buf.join('');
    }

    function _makeLogoutUri(redirectUri) {
        let query = {
            post_logout_redirect_uri: redirectUri
        };
        return _endpointUri('logout') + '?' + qs.stringify(query);
    }
}
