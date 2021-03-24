require('dotenv').config();
const express = require('express');
const app = express();
const massive = require('massive');
const session = require('express-session')
const authCtrl = require('./controllers/authCtrl');
const authenticateUser = require('./middlewares/authenticateUser');

const { PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(express.json());

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}));

// auth endpoints
app.post('/auth/register', authCtrl.register);
app.post('/auth/login', authCtrl.login);
app.delete('/auth/logout', authCtrl.logout);

// protected routes
app.get('/api/secret', authenticateUser, (req, res) => {
    res.status(200).send("Here's the secret!")
})

massive({
    connectionString: CONNECTION_STRING,
    ssl: {
        rejectUnauthorized: false
    }
})
.then(dbInstance => {
    app.set('db', dbInstance);
    app.listen(PORT, () => console.log(`DB up & Server running on ${PORT}`));
})
.catch(err => console.log(err));