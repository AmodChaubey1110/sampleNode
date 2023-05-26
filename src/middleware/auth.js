const jwtt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
	try {
		const token = req.headers.authorization.split(' ')[1];
		const apiKey = req.headers.apikey;
		const decode = jwtt.verify(token, 'thisisnodeapis');
		const user = await User.findOne({ _id: decode._id });
		console.log('apiKey:::', apiKey);

		if (!user) {
			throw new Error('no match');
		}

		req.token = token;
		req.user = user;
		if (user || apiKey === 'Aspire@123') {
			next();
		}
	} catch (error) {
		console.log('::::', error);
		res.status(401).send('Invalid Token');
	}
};

module.exports = { auth };
