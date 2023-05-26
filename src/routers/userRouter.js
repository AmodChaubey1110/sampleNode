const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { auth } = require('../middleware/auth');

router.post('/users', async (req, res) => {
	const user = new User(req.body);

	try {
		await user.save();
		const token = await user.generateAuthToken();
		res.status(201).send({ user, token });
	} catch (e) {
		res.status(400).send(e);
	}
});

router.get('/users/me', auth, (req, res) => {
	res.send(req.user);
});

router.post('/users/login', async (req, res) => {
	try {
		const user = await User.findByCredentials(
			req.body.email,
			req.body.password
		);
		const token = await user.generateAuthToken();
		res.status(200).send({ user, token });
	} catch (error) {
		console.log('error', error);
		res.status(400).send(error);
	}
});

router.post('/users/logout', auth, async (req, res) => {
	try {
		req.user.tokens = req.user.tokens.filter((token) => {
			return token.token !== req.token;
		});
		await req.user.save();
		res.send();
	} catch (error) {
		res.status(500).send();
	}
});

router.post('/users/logoutAll', auth, async (req, res) => {
	try {
		req.user.tokens = [];
		await req.user.save();
		res.send();
	} catch (error) {
		res.status(500).send();
	}
});

router.patch('/users/me', auth, async (req, res) => {
	const updates = Object.keys(req.body);
	const allowedUpdate = ['name', 'email', 'password', 'age'];
	const validOperation = updates.every((update) => {
		return allowedUpdate.includes(update);
	});
	if (!validOperation) {
		return res.status(400).send({ error: 'Cant update' });
	}
	try {
		updates.forEach(async (update) => {
			req.user[update] = req.body[update];
		});
		await req.user.save();
		res.send(req.user);
	} catch (e) {
		console.log('err:::::', e);
		res.status(400).send(e);
	}
});

router.delete('/user/me', auth, async (req, res) => {
	try {
		const user = await User.findByIdAndDelete(req.user._id);

		await req.user.remove();
		res.send(req.user);
	} catch (error) {
		res.status(500).send();
	}
});

module.exports = router;
