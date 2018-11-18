const express = require("express");
const authRoutes = express.Router();
const session = require("express-session");
const bcrypt = require("bcrypt");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const ensureLogin = require("connect-ensure-login");
const flash = require("connect-flash");

app.use(session({
	secret: "our-passport-local-strategy-app",
	resave: true,
	saveUninitialized: true
}));

app.use(flash());

passport.serializeUser((user, cb) => {
	cb(null, user._id);
});

passport.deserializeUser((id, cb) => {
	User.findById(id, (err, user) => {
		if (err) {
			return cb(err);
		}
		cb(null, user);
	});
});

passport.use(new LocalStrategy({
	passReqToCallback: true
}, (req, username, password, next) => {
	User.findOne({
		username
	}, (err, user) => {
		if (err) {
			return next(err);
		}
		if (!user) {
			return next(null, false, {
				message: "Incorrect username"
			});
		}
		if (!bcrypt.compareSync(password, user.password)) {
			return next(null, false, {
				message: "Incorrect password"
			});
		}

		return next(null, user);
	});
}));

app.use(passport.initialize());
app.use(passport.session());

// User model
const User = require("../models/user");

// Bcrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;

authRoutes.get("/signup", (req, res, next) => {
	res.render("auth/signup");
});

authRoutes.post("/signup", (req, res, next) => {
	const username = req.body.username;
	const password = req.body.password;

	if (username === "" || password === "") {
		res.render("auth/signup", {
			message: "Indicate username and password"
		});
		return;
	}

	User.findOne({
			username
		})
		.then(user => {
			if (user !== null) {
				res.render("auth/signup", {
					message: "The username already exists"
				});
				return;
			}

			const salt = bcrypt.genSaltSync(bcryptSalt);
			const hashPass = bcrypt.hashSync(password, salt);

			const newUser = new User({
				username,
				password: hashPass
			});

			newUser.save((err) => {
				if (err) {
					res.render("auth/signup", {
						message: "Something went wrong"
					});
				} else {
					res.redirect("/");
				}
			});
		})
		.catch(error => {
			next(error)
		})
});

authRoutes.get("/login", (req, res, next) => {
	res.render("auth/login", {
		"message": req.flash("error")
	});
});

authRoutes.post("/login", passport.authenticate("local", {
	successRedirect: "/",
	failureRedirect: "/login",
	failureFlash: true,
	passReqToCallback: true
}));

authRoutes.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
	res.render("private", {
		user: req.user
	});
});

authRoutes.get("/logout", (req, res) => {
	req.logout();
	res.redirect("/login");
});