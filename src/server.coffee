###
# nodejs-express-mongoose-demo
# Copyright(c) 2013 Madhusudhan Srinivasa <madhums8@gmail.com>
# MIT Licensed
###

## Module dependencies.

express = require('express')
fs = require('fs')
passport = require('passport')

# Main application entry file.
# Please note that the order of loading is important.

# Load configurations
# if test env, load example file
env = process.env.NODE_ENV || 'development'
config = require('./config/config')[env]
auth = require('./config/middlewares/authorization')
mongoose = require('mongoose')

# Bootstrap db connection
mongoose.connect(config.db)

# Bootstrap models
models_path = __dirname + '/app/models'
fs.readdirSync(models_path).forEach (file)-> require(models_path+'/'+file)

# bootstrap passport config
require('./config/passport')(passport, config)

app = express();
# express settings
require('./config/express')(app, config, passport)

# Bootstrap routes
require('./config/routes')(app, passport, auth)

# Start the app by listening on <port>
port = process.env.PORT || 3000
app.listen(port)
console.log "Express app started on port #{port}"

# expose app
exports = module.exports = app

