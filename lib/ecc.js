var ecc = require('../build/Release/native.node');

ecc.ECKey.prototype.inspect = function () {
	return '<ECKey>';
}

module.exports = ecc;
