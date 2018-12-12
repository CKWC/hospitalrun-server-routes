var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var bodyParser = require('body-parser');
var express = require('express');
var expressSession = require('express-session');
var passport = require('passport');
var makeAuth = require('../auth.js');

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete Google profile is
//   serialized and deserialized.
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

module.exports = function(app, config) {

  var auth = makeAuth(config);

  /*eslint new-cap: ["error", { "capIsNewExceptions": ["Router"] }]*/
  var router = express.Router();
  router.use(bodyParser.json());
  router.use(bodyParser.urlencoded({
    extended: true
  }));
  router.use(expressSession({secret: 'health matters', resave: true, saveUninitialized: false}));

  // Use the GoogleStrategy within Passport.
  //   Strategies in Passport require a `verify` function, which accept
  //   credentials (in this case, an accessToken, refreshToken, and Google
  //   profile), and invoke a callback with a user object.
  passport.use(
      new GoogleStrategy({
        clientID: config.googleClientId,
        clientSecret: config.googleClientSecret,
        callbackURL: config.serverURL + '/auth/google/callback',
        passReqToCallback: true
    }, auth.findOAuthUser)
  );

  // Initialize Passport!  Also use passport.session() middleware, to support
  // persistent login sessions (recommended).
  router.use(passport.initialize());
  router.use(passport.session());
  // GET /auth/google
  //   Use passport.authenticate() as route middleware to authenticate the
  //   request.  The first step in Google authentication will involve
  //   redirecting the user to google.com.  After authorization, Google
  //   will redirect the user back to this application at /auth/google/callback
  router.get('/auth/google', function (req, res) {
    console.log('google auth request for: ' + req.hostname);

    passport.authenticate('google', {
      state: req.hostname,
      scope: ['https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/userinfo.email',],
    })(req, res);
  });

  // GET /auth/google/callback
  //   Use passport.authenticate() as route middleware to authenticate the
  //   request.  If authentication fails, the user will be redirected back to the
  //   login page.  Otherwise, the primary route function function will be called,
  //   which, in this example, will redirect the user to the home page.
  router.get('/auth/google/callback',
    passport.authenticate('google', {failureRedirect: '/#/login'}),
    function(req, res) {
      var user = req.user;
      var hostname = req.query.state;

      redirURL = '';
      if (config.isMultitenancy) {
        redirURL += 'https://' + hostname;
      }

      redirURL += '/#/finishgauth/';
      redirURL += user.consumer_secret;
      redirURL += '/' + user.token_secret;
      redirURL += '/' + user.consumer_key;
      redirURL += '/' + user.token_key;
      redirURL += '/' + user.name;
      redirURL += '/' + user.userPrefix;
      res.redirect(redirURL);
    }
  );

  function getSession(req, res, requestOptions, includeOauth) {
    return auth.getSession(req, requestOptions, includeOauth, req.body.name,
      function (response) {
        res.json(response);
      });
  }

  router.post('/auth/login', function(req, res) {
    var requestOptions = {
      method: 'POST',
      form: req.body
    };
    getSession(req, res, requestOptions, true);
  });

  router.post('/chkuser', function(req, res) {
    var requestOptions = {};
    if (req.get('x-oauth-consumer-key')) {
      requestOptions.oauth = {
        consumer_key: req.get('x-oauth-consumer-key'),
        consumer_secret: req.get('x-oauth-consumer-secret'),
        token: req.get('x-oauth-token'),
        token_secret: req.get('x-oauth-token-secret')
      };
    }
    getSession(req, res, requestOptions, false);
  });

  router.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
  });
  app.use('/', router);
};
