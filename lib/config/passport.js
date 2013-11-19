// Generated by CoffeeScript 1.6.3
(function() {
  var FacebookStrategy, GitHubStrategy, GoogleStrategy, LocalStrategy, TwitterStrategy, User, mongoose;

  mongoose = require('mongoose');

  LocalStrategy = require('passport-local').Strategy;

  TwitterStrategy = require('passport-twitter').Strategy;

  FacebookStrategy = require('passport-facebook').Strategy;

  GitHubStrategy = require('passport-github').Strategy;

  GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

  User = mongoose.model('User');

  module.exports = function(passport, config) {
    var callbackUserFindOne, facebookStrategy, gitHubStrategy, googleStrategy, localStrategy, twitterStrategy;
    passport.serializeUser(function(user, done) {
      return done(null, user.id);
    });
    passport.deserializeUser(function(id, done) {
      return User.findOne({
        _id: id
      }, function(err, user) {
        return done(err, user);
      });
    });
    callbackUserFindOne = function(err, user) {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false, {
          message: 'Unknown user'
        });
      }
      if (!user.authenticate(password)) {
        return done(null, false, {
          message: 'Invalid password'
        });
      }
      return done(null, user);
    };
    localStrategy = new LocalStrategy({
      usernameField: 'email',
      passwordField: 'password'
    });
    passport.use(localStrategy, function(email, password, done) {
      return User.findOne({
        email: email
      }, callbackUserFindOne);
    });
    twitterStrategy = new TwitterStrategy({
      consumerKey: config.twitter.clientID,
      consumerSecret: config.twitter.clientSecret,
      callbackURL: config.twitter.callbackURL
    });
    passport.use(twitterStrategy, function(token, tokenSecret, profile, done) {
      User.findOne({
        'twitter.id': profile.id
      }, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          user = new User({
            name: profile.displayName,
            username: profile.username,
            provider: 'twitter',
            twitter: profile._json
          });
          user.save(function(err) {
            if (err != null) {
              console.log(err);
            }
            return done(err, user);
          });
        } else {
          return done(err, user);
        }
      });
    });
    facebookStrategy = new FacebookStrategy({
      clientID: config.facebook.clientID,
      clientSecret: config.facebook.clientSecret,
      callbackURL: config.facebook.callbackURL
    });
    passport.use(facebookStrategy, function(accessToken, refreshToken, profile, done) {
      User.findOne({
        'facebook.id': profile.id
      }, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          user = new User({
            name: profile.displayName,
            email: profile.emails[0].value,
            username: profile.username,
            provider: 'facebook',
            facebook: profile._json
          });
          user.save(function(err) {
            if (err != null) {
              console.log(err);
            }
            return done(err, user);
          });
        } else {
          return done(err, user);
        }
      });
    });
    gitHubStrategy = new GitHubStrategy({
      clientID: config.github.clientID,
      clientSecret: config.github.clientSecret,
      callbackURL: config.github.callbackUR
    });
    passport.use(gitHubStrategy, function(accessToken, refreshToken, profile, done) {
      User.findOne({
        'github.id': profile.id
      }, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          user = new User({
            name: profile.displayName,
            email: profile.emails[0].value,
            username: profile.username,
            provider: 'github',
            github: profile._json
          });
          user.save(function(err) {
            if (err != null) {
              console.log(err);
            }
            return done(err, user);
          });
        } else {
          return done(err, user);
        }
      });
    });
    googleStrategy = new GoogleStrategy({
      clientID: config.google.clientID,
      clientSecret: config.google.clientSecret,
      callbackURL: config.google.callbackURL
    });
    return passport.use(googleStrategy, function(accessToken, refreshToken, profile, done) {
      User.findOne({
        'google.id': profile.id
      }, function(err, user) {
        var new_profile;
        if (!user) {
          new_profile = {};
          new_profile.id = profile.id;
          new_profile.displayName = profile.displayName;
          new_profile.emails = profile.emails;
          user = new User({
            name: profile.displayName,
            email: profile.emails[0].value,
            username: profile.username,
            provider: 'google',
            google: new_profile._json
          });
          user.save(function(err) {
            if (err != null) {
              console.log(err);
            }
            return done(err, user);
          });
        } else {
          return done(err, user);
        }
      });
    });
  };

}).call(this);