
const express = require('express');
const session = require('express-session');
const connectMongo = require('connect-mongo');
const { MongoClient } = require('mongodb');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;


const mongoUrl = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`;

const client = new MongoClient(mongoUrl);


const MongoStore = connectMongo.create({
  client: client,
  dbName: process.env.MONGODB_DATABASE,
  collectionName: 'sessions',
  crypto: {
    secret: process.env.MONGODB_SESSION_SECRET
  }
});

app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore,
    cookie: {
      maxAge: 60 * 60 * 1000,
    },
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

async function run() {
  try {
    await client.connect();
    console.log('Connected successfully to MongoDB');

    // --- ROUTES ---
    app.get('/', home);
    app.get('/signup', signup);
    app.post('/signup', signupPost);
    app.get('/login', login);
    app.post('/login', loginPost);
    app.get('/logout', logout);
    app.get('/members', members);
    app.use(error404);

    app.listen(port, () => {
      console.log(`Server listening on port ${port}`);
    });
  } catch (err) {
    console.error('Error connecting to MongoDB', err);
  }
}

run().catch(console.dir);


const isLoggedIn = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/');
  }
};

async function home(req, res) {
  if (req.session.user) {
    res.render('home', { user: req.session.user });
  } else {
    res.render('home', { user: null });
  }
}

async function signup(req, res) {
  res.render('signup');
}

async function signupPost(req, res) {
  const schema = Joi.object({
    name: Joi.string().max(255).required(),
    email: Joi.string().email().max(255).required(),
    password: Joi.string().min(6).max(255).required(),
  });

  const { error, value } = schema.validate(req.body);

  if (error) {
    return res.status(400).send(error.details[0].message);
  }

  try {
    const db = client.db(process.env.MONGODB_DATABASE);
    const users = db.collection('users');


    const existingUser = await users.findOne({ email: value.email });
    if (existingUser) {
      return res.status(400).send('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(value.password, 10);

    const newUser = {
      name: value.name,
      email: value.email,
      password: hashedPassword,
    };
    await users.insertOne(newUser);

    req.session.user = { name: value.name, email: value.email };

    res.redirect('/members');
  } catch (err) {
    console.error('Error during signup', err);
    res.status(500).send('Error signing up');
  }
}

async function login(req, res) {
  res.render('login');
}

async function loginPost(req, res) {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  });

  const { error, value } = schema.validate(req.body);

  if (error) {
    return res.status(400).send(error.details[0].message);
  }

  try {
    const db = client.db(process.env.MONGODB_DATABASE);
    const users = db.collection('users');

    const user = await users.findOne({ email: value.email });

    if (!user) {
      return res.status(400).send('Invalid email/password combination');
    }

    const passwordMatch = await bcrypt.compare(value.password, user.password);

    if (passwordMatch) {
      req.session.user = { name: user.name, email: user.email };
      res.redirect('/members');
    } else {
      return res.status(400).send('Invalid email/password combination');
    }
  } catch (err) {
    console.error('Error during login', err);
    res.status(500).send('Error logging in');
  }
}

async function logout(req, res) {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session', err);
    }
    res.redirect('/');
  });
}

async function members(req, res) {
  if (req.session.user) {
    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];
    res.render('members', { user: req.session.user, randomImage: randomImage });
  } else {
    res.redirect('/');
  }
}

async function error404(req, res) {
  res.status(404).send('Page not found');
}