const express = require('express');
const session = require('express-session');
const connectMongo = require('connect-mongo');
const { MongoClient } = require('mongodb');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
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
});

// --- Encryption Setup ---
const SESSION_ENCRYPTION_SALT = process.env.SESSION_ENCRYPTION_SALT; // From .env!
const AES_ALGORITHM = 'aes-256-ctr';
const ENCRYPTION_KEY_LENGTH = 32; // 256 bits

let encryptionKey; // Store the derived key

async function deriveEncryptionKey() {
  if (!SESSION_ENCRYPTION_SALT) {
    console.error('ERROR: SESSION_ENCRYPTION_SALT is not defined in .env!');
    throw new Error('SESSION_ENCRYPTION_SALT is not defined'); // Prevent server start
  }
  try {
    const derivedKey = await bcrypt.hash(SESSION_ENCRYPTION_SALT, 10);
    encryptionKey = derivedKey.substring(0, ENCRYPTION_KEY_LENGTH);
  } catch (error) {
    console.error('Error deriving encryption key:', error);
    throw error; // Propagate the error
  }
}

function encryptSessionData(data) {
  const iv = crypto.randomBytes(16).toString('hex');
  const cipher = crypto.createCipheriv(AES_ALGORITHM, encryptionKey, Buffer.from(iv, 'hex'));
  let encryptedData = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encryptedData += cipher.final('hex');
  return { iv, encryptedData };
}

function decryptSessionData(encryptedData, iv) {
  const decipher = crypto.createDecipheriv(AES_ALGORITHM, encryptionKey, Buffer.from(iv, 'hex'));
  const decrypted = decipher.update(encryptedData, 'hex', 'utf8') + decipher.final('utf8');
  return JSON.parse(decrypted);
}

app.use(
  session({
    secret: process.env.MONGODB_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore,
    cookie: {
      maxAge: 60 * 60 * 1000,
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'strict',
    },
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

async function run() {
  try {
    await client.connect();
    console.log('Connected to MongoDB');

    await deriveEncryptionKey(); // Derive the key

    // --- ROUTES ---
    app.get('/', home);
    app.get('/signup', signup);
    app.post('/signup', signupPost);
    app.get('/login', login);
    app.post('/login', loginPost);
    app.get('/logout', logout);
    app.get('/members', members);
    app.use(error404);

    app.listen(port, () => console.log(`Server listening on port ${port}`));
  } catch (error) {
    console.error('Server startup error:', error);
  }
}

run().catch(console.error);

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
      const sessionData = { name: user.name, email: user.email };
      const { iv, encryptedData } = encryptSessionData(sessionData);

      req.session.encryptedData = encryptedData;
      req.session.iv = iv;
      req.session.userId = user._id; // Store user ID separately

      req.session.regenerate((err) => {
        if (err) {
          console.error('Session error:', err);
          return res.status(500).send('Session error');
        }
        res.redirect('/members');
      });
    } else {
      return res.status(400).send('Invalid credentials');
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send('Login failed');
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
  if (!req.session.userId) {
    return res.redirect('/');
  }

  try {
    const decryptedSession = decryptSessionData(req.session.encryptedData, req.session.iv);

    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];
    res.render('members', { user: decryptedSession, randomImage });
  } catch (error) {
    console.error('Members area error:', error);
    res.status(500).send('Error accessing members area');
  }
}

async function error404(req, res) {
  res.status(404).send('Page not found');
}