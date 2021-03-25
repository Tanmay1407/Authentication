//jshint esversion:6

require("dotenv").config();
//const md5 = require("md5");
//const bcrypt = require("bcryptjs");

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
//const encrypt = require("mongoose-encryption");
const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: 'My Long Password Key.',
  resave: false,
  saveUninitialized: true,
  // cookie:{secure: true}
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email :String,
  password: String,
  googleId: String,
  secrets: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt,{secret: process.env.MYKEY , encryptedFields: ['password']});

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user,done)=>{
//user.id is not profile id. it is id that created by the database
    done(null,user.id)
})
passport.deserializeUser((id,done)=>{
    User.findById(id).then((user)=>{
        done(null,user)
    })
})

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res) {
  res.render("home")
});


app.route("/submit")
.get( function(req,res){
  if(req.isAuthenticated())
res.render("submit");
else res.redirect("/login");
})
.post(function(req,res){
    const userSecret = req.body.secret;

  User.findById(req.user.id, function(err,foundUser){
    if(err)
    console.log(err);
    else {
      foundUser.secrets = userSecret;
      foundUser.save(function(){
        res.redirect("/secrets");
      });
    }

  });
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.route("/login")
.get(function(req, res) {
  res.render("login")
})
.post(function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  })


});


app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/logout", function(req,res){
  req.logout();
  res.redirect("/");
});

app.route("/register")
.get(function(req, res) {
  res.render("register")
})
.post(function(req, res) {

  User.register({username: req.body.username},req.body.password, function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");

    }else{
      passport.authenticate("local")(req,res, function(){
        res.redirect("/secrets");
      })
    }
  })

  });


app.get("/secrets", function(req,res){
  if(req.isAuthenticated()){
User.find({"secrets":{$ne: null}}, function(err,foundUsers){
  if(err){
    console.log(err);
    res.redirect("/login");
  }else{
    if(foundUsers){
      res.render("secrets",{usersWithSecrets: foundUsers});
    }
  }
});}
else res.redirect("/login");

});


app.listen(process.env.PORT || 3000, function() {
  console.log("Server rolling at port 3000....");
});
