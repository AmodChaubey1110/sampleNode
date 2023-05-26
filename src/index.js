const express = require('express');
const UserRouter = require('./routers/userRouter');
const app = express();
require('./db/mongoose');

const port = process.env.PORT || 4000;

app.use(express.json());
app.use(UserRouter);

app.listen(port, () => {
	console.log('Server is running on ', port);
});
