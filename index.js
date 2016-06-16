const session = require('./lib/session');
const proxy = require('./lib/proxy');
const token = require('./lib/token');
const auth = require('./lib/auth');

module.exports = function(app, options) {
    session(app, options);
    token(app, options);
    proxy(app, options);
    auth(app, options);
}
