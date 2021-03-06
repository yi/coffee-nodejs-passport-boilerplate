// Generated by CoffeeScript 1.6.3
(function() {
  var User, mongoose;

  mongoose = require('mongoose');

  User = mongoose.model('User');

  exports.signin = function(req, res) {};

  exports.authCallback = function(req, res, next) {
    res.redirect('/');
  };

  exports.login = function(req, res) {
    res.render('users/login', {
      title: 'Login',
      message: req.flash('error')
    });
  };

  exports.signup = function(req, res) {
    res.render('users/signup', {
      title: 'Sign up',
      user: new User()
    });
  };

  exports.logout = function(req, res) {
    req.logout();
    res.redirect('/login');
  };

  exports.session = function(req, res) {
    res.redirect('/');
  };

  exports.create = function(req, res) {
    var newUser;
    newUser = new User(req.body);
    newUser.provider = 'local';
    User.findOne({
      email: newUser.email
    }).exec(function(err, user) {
      if (err != null) {
        return next(err);
      }
      if (user == null) {
        newUser.save(function(err) {
          if (err != null) {
            res.render('users/signup', {
              errors: err.errors,
              user: newUser
            });
            return;
          }
          req.logIn(newUser, function(err) {
            if (err != null) {
              return next(err);
            }
            return res.redirect('/');
          });
        });
      } else {
        res.render('users/signup', {
          errors: [
            {
              "type": "email already registered"
            }
          ],
          user: newUser
        });
        return;
      }
    });
  };

  exports.show = function(req, res) {
    User.findOne({
      _id: req.params['userId']
    }).exec(function(err, user) {
      if (err != null) {
        return next(err);
      }
      if (user == null) {
        return next(new Error('Failed to load User ' + id));
      }
      res.render('users/show', {
        title: user.name,
        user: user
      });
    });
  };

  exports.user = function(req, res, next, id) {
    User.findOne({
      _id: id
    }).exec(function(err, user) {
      if (err != null) {
        return next(err);
      }
      if (user == null) {
        return next(new Error('Failed to load User ' + id));
      }
      req.profile = user;
      next();
    });
  };

}).call(this);
