const { securityHeaders } = require('./lib/headers');
module.exports = { headers: () => securityHeaders };
