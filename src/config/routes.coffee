
async = require "async"

module.exports = (app, passport, auth)->

  # user routes
  users = require "../controllers/users"
  app.get '/login', users.login
  app.get '/signup', users.signup
  app.get '/logout', users.logout
  app.post '/users', users.create
  app.post '/users/session', passport.authenticate('local', {failureRedirect: '/login', failureFlash: 'Invalid email or password.'}), users.session
  app.get '/users/:userId', users.show
  app.get '/auth/facebook', passport.authenticate('facebook', { scope: [ 'email', 'user_about_me'], failureRedirect: '/login' }), users.signin
  app.get '/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login' }), users.authCallback
  app.get '/auth/github', passport.authenticate('github', { failureRedirect: '/login' }), users.signin
  app.get '/auth/github/callback', passport.authenticate('github', { failureRedirect: '/login' }), users.authCallback
  app.get '/auth/twitter', passport.authenticate('twitter', { failureRedirect: '/login' }), users.signin
  app.get '/auth/twitter/callback', passport.authenticate('twitter', { failureRedirect: '/login' }), users.authCallback
  #app.get '/auth/google', passport.authenticate('google', { failureRedirect: '/login', scope: 'https:#www.google.com/m8/feeds' }), users.signin)
  #app.get '/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login', scope: 'https:#www.google.com/m8/feeds' }), users.authCallback)

  app.get '/auth/google', passport.authenticate('google', { scope: ['https:#www.googleapis.com/auth/userinfo.profile', 'https:#www.googleapis.com/auth/userinfo.email'] })
  app.get '/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login', successRedirect: '/' })

  # this is home page
  home = require "../controllers/home"
  app.get '/', home.index
