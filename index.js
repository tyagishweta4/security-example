import https from 'https';
import fs from 'fs';
import express from 'express';
import helmet from 'helmet';
import passport from 'passport';
import dotenv from 'dotenv';
import { Strategy } from 'passport-google-oauth20';
import cookieSession from 'cookie-session';

dotenv.config();
const PORT = 3000;

const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2
};

const authOptions = {
    callbackURL: '/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET,
};
const verifyCallback = (accessToken, refreshToken, profile, done) => {
    console.log(`groogle profile ${profile}`);
    done(null, profile);
}
passport.use(new Strategy(authOptions, verifyCallback))
passport.serializeUser((user, done) => {
    done(null, user.id);
})
passport.deserializeUser((id, done) => {
    done(null, id);
})
const app = express();
app.use(helmet());
app.use(cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
}))
app.use(passport.initialize())
app.use(passport.session());

const checkIfLoggedIn = (req, res, next) => {
    const isLoggedIn = req.isAuthenticated() && req.user;
    if (!isLoggedIn)
        return res.status(401).json({
            error: 'you must login'
        })
    next();
}

app.get('/auth/google', passport.authenticate('google', {
    scope: ['email']
}))

app.get('/auth/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/failure',
        successRedirect: '/',
        session: true,
    }, (req, res) => {
        console.log('google called us back')
    }))

app.get('/auth/logout', (req, res) => {
    if (req.isAuthenticated() && req.user) {
        req.logout();
        return res.redirect('/');
    }
})

app.get('/secret', checkIfLoggedIn, (req, res) => {
    return res.send("hello world");
})

app.get('/failure', (req, res) => {
    return res.send("failed to login");
})

app.get('/', (req, res) => {
    return res.send("hello route");
})

https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
}, app).listen(PORT, () => {
    console.log(`Listining on port ${PORT}`)
})