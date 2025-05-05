// app.js
const express = require('express');
const session = require('express-session');
const connectMongo = require('connect-mongo');
const { MongoClient } = require('mongodb');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path'); // For serving static files (images)

dotenv.config(); // Load environment variables from .env

const app = express();
const port = process.env.PORT || 3000;

// MongoDB Connection URL
const mongoUrl = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`;

const client = new MongoClient(mongoUrl);

// Session store
const MongoStore = connectMongo.create({
  client: client,
  dbName: process.env.MONGODB_DATABASE,
  collectionName: 'sessions',
});

// Session middleware
app.use(
  session({
    secret: process.env.MONGODB_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore,
    cookie: {
      maxAge: 60 * 60 * 1000, // 1 hour
    },
  })
);

app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(express.static('public')); // Serve static files from 'public' directory
app.set('view engine', 'ejs'); // Set 'ejs' as the template engine

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

// --- Route Handlers ---

// Helper function to check if user is logged in
const isLoggedIn = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/');
  }
};

// 1. Home page -site: / method: GET
async function home(req, res) {
  if (req.session.user) {
    res.render('home', { user: req.session.user }); // Render home page for logged-in user
  } else {
    res.render('home', { user: null }); // Render home page for not logged-in user
  }
}

// 2. Sign up page -site:/signup method: GET
async function signup(req, res) {
  res.render('signup'); //display the signup form
}

async function signupPost(req, res) {
  // Validation schema using Joi
  const schema = Joi.object({
    name: Joi.string().max(255).required(),
    email: Joi.string().email().max(255).required(),
    password: Joi.string().min(6).max(255).required(), // Adjust min/max as needed
  });

  const { error, value } = schema.validate(req.body);

  if (error) {
    return res.status(400).send(error.details[0].message); // Send validation error
  }

  try {
    const db = client.db(process.env.MONGODB_DATABASE);
    const users = db.collection('users');

    // Check if email already exists
    const existingUser = await users.findOne({ email: value.email });
    if (existingUser) {
      return res.status(400).send('Email already exists');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(value.password, 10);

    // Insert the new user
    const newUser = {
      name: value.name,
      email: value.email,
      password: hashedPassword,
    };
    await users.insertOne(newUser);

    // Create session
    req.session.user = { name: value.name, email: value.email };

    res.redirect('/members'); // Redirect to members area
  } catch (err) {
    console.error('Error during signup', err);
    res.status(500).send('Error signing up');
  }
}

// 3. Log in page -site:/login method: GET
async function login(req, res) {
  res.render('login');
}

async function loginPost(req, res) {
  // Validation schema for login
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

// 5. Log out page -site:/logout method: GET
async function logout(req, res) {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session', err);
    }
    res.redirect('/');
  });
}

// 4. Members only page - site: /members method: GET
async function members(req, res) {
  if (req.session.user) {
    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];
    res.render('members', { user: req.session.user, randomImage: randomImage });
  } else {
    res.redirect('/');
  }
}

// 6. 404 page - site: any non-assigned URLs method: GET
async function error404(req, res) {
  res.status(404).send('Page not found');
}