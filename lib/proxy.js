//==============================================================================
// Usage: proxy(app, options);
//==============================================================================
// Copyright (c) 2016 Frank Hellwig
//==============================================================================

'use strict';

const proxy = require('express-request-proxy');

const TIMEOUT = 120 * 1000;

module.exports = function(app, options) {
    const path = options.localApiPath + '/*';
    const url = options.remoteApiUri + '/*';

    app.all(path, proxy({
        url: url,
        timeout: TIMEOUT
    }));
}
