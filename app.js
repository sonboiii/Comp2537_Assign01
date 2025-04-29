const express = require('express');
const session = require('express-session');

const app = express();
const port = process.env.PORT || 3000;

//let pageHist = 0;

const node_session_secret = '208a726f-80a0-419c-814a-bc4f4c0e9ae7';

app.use(session({
    secret: node_session_secret,
    saveUninitialized: false,
    resave: true,
}));

// Routes
app.get('/', (req, res) => {
    if (req.session.pageHist) {
        req.session.pageHist++;
    }
    else {
        req.session.pageHist = 1;
    }
    res.send('Hello, World!! :D  ' + req.session.pageHist + ' times!');
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});