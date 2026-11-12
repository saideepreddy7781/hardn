const helmet = require('helmet');
const app = require('express')();
app.use(helmet());
app.listen(3000);
