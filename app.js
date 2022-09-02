require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose")
// 1  require express session
const session = require("express-session")
// 2 require remaining
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")

const GoogleStrategy = require('passport-google-oauth2').Strategy;
const findOrCreate = require("mongoose-findorcreate")

const app = express();

app.use(express.static("public"));
app.use(express.urlencoded({
  extended: true
}));
app.set("view engine", "ejs");
//  3 set up session

app.use(session({
  secret: "Our Little secrete.",
  resave: false,
  saveUninitialized: false,

}))
// 4 telling passport to use session
app.use(passport.initialize())
app.use(passport.session())


//Set up default mongoose connection

const srvr = process.env.N1_KEY;
const srvrCred = process.env.N1_SECRET;

var mongoDB = "mongodb+srv://" + srvr + ":" + srvrCred + "@alberts-place.0nsi2.mongodb.net/secretsDB";
mongoose.connect(mongoDB, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

//Get the default connection
var db = mongoose.connection;

//Bind connection to error event (to get notification of connection errors)
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

const Schema = mongoose.Schema;

const userSchema = new Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

// 5 setup mongoose schema plugin
userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

const User = new mongoose.model("user", userSchema)

// 6 from npm website of passport-local-mongoose

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, {
      id: user.id,
      username: user.username
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

// auth2 2
passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  passReqToCallback: true
},
  function (request, accessToken, refreshToken, profile, done) {
    User.findOrCreate({
      googleId: profile.id
    }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get('/', (req, res) => {
  res.render('home');
});


app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email']
  })
);
app.get("/auth/google/secrets",
  passport.authenticate('google', {
    successRedirect: "/secrets",
    failureRedirect: "/login"
  }));
app.get('/login', (req, res) => {
  res.render('login');
});
app.post('/login', (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  })
  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      })
    }
  })

});

app.get('/register', (req, res) => {
  res.render('register');
});

app.get("/secrets", function (req, res) {
  User.find({
    "secret": {
      $ne: null
    }
  }, function (err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {
          userWithSecrets: foundUsers
        })
      }
    }
  })
})
app.post('/register', (req, res) => {
  User.register({
    username: req.body.username
  }, req.body.password, function (err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register")
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      })
    }
  })

});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (!err) {
      res.redirect("/")
    }
  })

})
app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login")
  }
})
app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret
        foundUser.save(function () {
          res.redirect("/secrets");
        })
      }
    }
  })
})

const port = process.env.PORT || 3000;

app.listen(port, function () {
  console.log("Server started successfully");
});