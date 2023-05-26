const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
	name: {
		type: String,
		required: true,
		trime: true,
	},

	email: {
		type: String,
		unique: true,
		required: true,
		trime: true,
		validate(value) {
			if (!validator.isEmail(value)) {
				throw new Error('Email is invalid');
			}
		},
	},
	password: {
		type: String,
		required: true,
		trime: true,
		minlength: 7,
		validate(value) {
			if (value.toLowerCase().includes('password')) {
				throw new Error('Password cannot contain "password" ');
			}
		},
	},
	age: {
		type: Number,
		default: 0,
		validate(value) {
			if (value < 0) {
				throw new Error('Invalid Age Number');
			}
		},
	},
	tokens: [
		{
			token: {
				type: String,
				required: true,
			},
		},
	],
});

userSchema.methods.toJSON = function (params) {
	const user = this;
	const userObject = user.toObject();

	delete userObject.password;
	delete userObject.tokens;

	return userObject;
};

userSchema.methods.generateAuthToken = async function (params) {
	const user = this;
	const token = jwt.sign({ _id: user._id.toString() }, 'thisisnodeapis');
	user.tokens = user.tokens.concat({ token });
	await user.save();
	console.log('token', token);
	return token;
};

userSchema.statics.findByCredentials = async (email, password) => {
	const user = await User.findOne({ email });
	if (!user) {
		throw new Error('Unable to Login');
	}
	const isMatch = await bcrypt.compare(password, user.password);

	if (!isMatch) {
		throw new Error('Unable to Login');
	}
	return user;
}; //static method for login

userSchema.pre('save', async function (next) {
	const user = this;
	if (user.isModified('password')) {
		user.password = await bcrypt.hash(user.password, 8);
	}

	next();
}); //hashing the plain text password before saving

//delete  user's task when user is deleted
userSchema.pre('remove', async function (params) {
	const user = this;
	await Task.deleteMany({
		owner: user._id,
	});
});

const User = mongoose.model('User', userSchema);

module.exports = User;
