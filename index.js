require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { database } = require('./databaseConnection');
const path = require('path');

const port = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000; 

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

let userCollection;

(async () => {
    await database.connect();
    userCollection = database.db(mongodb_database).collection('users');

    var mongoStore = MongoStore.create({
        mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
        crypto: { secret: mongodb_session_secret }
    });

    app.use(session({
        secret: node_session_secret,
        store: mongoStore,
        saveUninitialized: false,
        resave: true,
        cookie: { maxAge: expireTime }
    }));

    app.get('/', (req, res) => {
        if (!req.session.name) {
            res.send(`
                <h2>Welcome!</h2>
                <a href="/signup"><button>Sign up</button></a>
                <a href="/login"><button>Log in</button></a>
            `);
        } else {
            res.send(`
                <div>
                    <div style="font-size: 1.5em; font-weight: bold;">Hello, ${req.session.name}!</div>
                    <div style="margin-top: 10px;"><a href="/members"><button>Go to Members Area</button></a></div>
                    <div style="margin-top: 5px;"><a href="/logout"><button>Logout</button></a></div>
                </div>
            `);
        }
    });

    app.get('/signup', (req, res) => {
        res.send(`
            <h2>Create User</h2>
            <form method="POST" action="/signupSubmit">
                <input name="name" placeholder="name"><br>
                <input name="email" placeholder="email"><br>
                <input name="password" type="password" placeholder="password"><br>
                <button type="submit">Submit</button>
            </form>
        `);
    });

    app.post('/signupSubmit', async (req, res) => {
        const schema = Joi.object({
            name: Joi.string().required(),
            email: Joi.string().email().required(),
            password: Joi.string().required()
        });
        const { error } = schema.validate(req.body);
        if (error) {
            return res.send(`
                <p>${error.details[0].message}</p>
                <a href="/signup">Try again</a>
            `);
        }
        const { name, email, password } = req.body;
        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
            return res.send('<p>Email already registered.</p><a href="/signup">Try again</a>');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await userCollection.insertOne({ name, email, password: hashedPassword });
        req.session.name = name;
        req.session.email = email;
        res.redirect('/members');
    });

    app.get('/login', (req, res) => {
        res.send(`
            <h2>Log In</h2>
            <form method="POST" action="/loginSubmit">
                <input name="email" placeholder="email"><br>
                <input name="password" type="password" placeholder="password"><br>
                <button type="submit">Submit</button>
            </form>
        `);
    });

    app.post('/loginSubmit', async (req, res) => {
        const schema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().required()
        });
        const { error } = schema.validate(req.body);
        if (error) {
            return res.send(`
                <p>${error.details[0].message}</p>
                <a href="/login">Try again</a>
            `);
        }
        const { email, password } = req.body;
        const user = await userCollection.findOne({ email });
        if (!user) {
            return res.send('<p>Invalid email/password combination.</p><a href="/login">Try again</a>');
        }
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.send('<p>Invalid email/password combination.</p><a href="/login">Try again</a>');
        }
        req.session.name = user.name;
        req.session.email = user.email;
        res.redirect('/members');
    });

    app.get('/members', (req, res) => {
        if (!req.session.name) {
            return res.redirect('/');
        }

        const imageFiles = [
            'photo-1735657090719-7f92cb44170b.avif',
            'photo-1735657090869-a81c50626bd3.avif',
            'photo-1735657061774-a9d62d06c954.avif'
        ];
        const randomImage = imageFiles[Math.floor(Math.random() * imageFiles.length)];
        res.send(`
            <h2>Hello, ${req.session.name}.</h2>
            <img src="/${randomImage}" style="max-width:300px;"><br>
            <a href="/logout"><button>Sign out</button></a>
        `);
    });

    app.get('/logout', (req, res) => {
        req.session.destroy(() => {
            res.redirect('/');
        });
    });

    app.use((req, res) => {
        res.status(404).send(`
            <h2>Page not found - 404</h2>
            <a href="/">Go Home</a>
        `);
    });

    app.listen(port, () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
})();