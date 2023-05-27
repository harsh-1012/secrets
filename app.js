//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require('mongoose-findorcreate');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

app.use(express.static("public"));
app.set('view engine',"ejs");
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
  secret: "Our little secret",
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://0.0.0.0:27017/userDB");

const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secrets:String
});

userSchema.plugin(findOrCreate);
userSchema.plugin(passportLocalMongoose);
//passport local mongoose module will do salting and hashing for us 

const User = mongoose.model("User",userSchema);

passport.use(User.createStrategy());
// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    done(null, user.id); 
   // where is this user.id going? Are we supposed to access this anywhere?
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    User.findById(id)
        .then(function(user){
            done(null,user);
        })
        .catch(function(err){
            done(err);
        });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.get("/secrets",function(req,res){
    User.find({"secrets":{$ne:null}})
        .then(function(foundList){
            res.render("secrets",{usersWithSecrets:foundList});
        });
});


app.get("/logout",function(req,res){
    req.logout(function(err){
        if(err){
            console.log(err);
        }else{
            res.redirect("/");
        }
    });
})

app.post("/register",function(req,res){

    User.register({username: req.body.username},req.body.password, function(err,user){
        if(err){
            console.log(err);
            redirect("/register");
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login",function(req,res){

    const user = new User({
        username : req.body.username,
        password : req.body.password
    });
    
    req.login(user,function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/submit",function(req,res){
    const submittedSecret = req.body.secret;

    User.findById(req.user._id)
        .then(function(foundUser){
            if(foundUser){
                foundUser.secrets = submittedSecret;
                foundUser.save();
                res.redirect("/secrets")
            }
        })
        .catch(function(err){
            console.log(err);
        });
});


app.listen(3000,function(){
    console.log("Server running at Port 3000");
});