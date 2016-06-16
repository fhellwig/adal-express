//==============================================================================
// Provides the get and renew access token functions. The options parameter
// must have the following four properties: azureTenantId azureClientId,
// azureClientSecret, and azureResourceUri.
//==============================================================================
// Copyright (c) 2016 Frank Hellwig
//==============================================================================

'use strict';

//------------------------------------------------------------------------------
// Dependencies
//------------------------------------------------------------------------------

const HttpsService = require('https-service');
const HttpsError = require('https-error');

//------------------------------------------------------------------------------
// Initialization
//------------------------------------------------------------------------------

const FIVE_MINUTES = 5 * 60;

const _aadService = new HttpsService('login.microsoftonline.com');

//------------------------------------------------------------------------------
// Exports
//------------------------------------------------------------------------------

module.exports = function(app, options) {
    app.use(options.localApiPath, _appendBearerToken);
};

module.exports.getToken = getToken;
module.exports.renewToken = renewToken;

//------------------------------------------------------------------------------
// Public
//------------------------------------------------------------------------------

function getToken(options, authorizationCode, replyUri, callback) {
    let body = {
        client_id: options.azureClientId,
        client_secret: options.azureClientSecret,
        code: authorizationCode,
        redirect_uri: replyUri,
        grant_type: 'authorization_code',
        resource: options.azureResourceUri
    };
    _aadPost(options.azureTenantId, body, (err, response) => {
        if (err) return callback(err);
        callback(null, _processResponse(response));
    });
}

function renewToken(options, refreshToken, callback) {
    let body = {
        client_id: options.azureClientId,
        client_secret: options.azureClientSecret,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        resource: options.azureResourceUri
    };
    _aadPost(options.azureTenantId, body, (err, response) => {
        if (err) return callback(err);
        callback(null, _processResponse(response));
    });
}

//------------------------------------------------------------------------------
// Private
//------------------------------------------------------------------------------

function _appendBearerToken(req, res, next) {
    const session = req.session;
    _ensureValidToken(session, err => {
        if (err) return next(err);
        if (typeof session.accessToken !== 'string') {
            return next(HttpsError.unauthorized('No accessToken property in session.'));
        }
        req.headers.authorization = 'Bearer ' + session.accessToken;
        if (!req.ext) {
            req.ext = {};
        }
        req.ext.isAuthenticated = true;
        next();
    });
}

function _ensureValidToken(session, callback) {
    if (typeof session.expiresAt !== 'number') {
        return callback(HttpsError.unauthorized('No expiresAt property in session.'));
    }
    if (Date.now() < session.expiresAt) {
        return callback(null); // the access token has not expired
    }
    renewToken(options, session.refreshToken, (err, response) => {
        if (err) return callback(err);
        Object.assign(session, response);
        session.touch();
        callback(null);
    });
}

function _processResponse(response) {
    const userClaims = _decodeClaims(response.access_token);
    const expiresIn = parseInt(response.expires_in);
    const expiresAt = Date.now() + (expiresIn - FIVE_MINUTES) * 1000;
    return {
        accessToken: response.access_token,
        refreshToken: response.refresh_token,
        userClaims: _decodeClaims(response.access_token),
        expiresAt: expiresAt
    };
}

function _decodeClaims(accessToken) {
    if (!accessToken) return null;
    let payload = accessToken.split('.')[1];
    let claims = JSON.parse(new Buffer(payload, 'base64').toString('ascii'));
    let retval = {
        userId: claims.oid,
        principalName: claims.upn || claims.unique_name,
        firstName: claims.given_name || '(no first name)',
        lastName: claims.family_name || '(no last name)',
        displayName: claims.name || '(no display name)'
    };
    return retval;
}

function _aadPost(tenantId, body, callback) {
    let path = `/${tenantId}/oauth2/token`;
    let headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    };
    _aadService.request('POST', path, headers, body, callback);
}
