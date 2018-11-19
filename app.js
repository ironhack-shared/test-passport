const express = require("express");

const app = express()
const session = require("express-session");
const bcrypt = require("bcrypt");
// Bcrypt to encrypt passwords
const bcryptSalt = 10;
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const ensureLogin = require("connect-ensure-login");
const flash = require("connect-flash");
const mongoose = require("mongoose")
const bodyParser = require('body-parser');
const path = require('path')
const hbs = require('hbs')

Swag = require('swag');

Swag.registerHelpers(hbs);

const User = require("./models/user");

mongoose.Promise = Promise;
mongoose
	.connect('mongodb://localhost/basic-auth')
	.then(() => {
		console.log('Connected to Mongo!')
	}).catch(err => {
		console.error('Error connecting to mongo', err)
	});

app.use(session({
	secret: "our-passport-local-strategy-app",
	resave: true,
	saveUninitialized: true
}));

app.use(flash());

app.use(express.static(path.join(__dirname, '/public')));
app.set('views', __dirname + '/views');
app.set('view engine', 'hbs');
hbs.registerPartials(__dirname + '/views/partials');

app.use(bodyParser.urlencoded({
	extended: true,
}));

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

app.get('/', ensureLogin.ensureLoggedIn(), (req, res) => {
	res.render('base', {
		user: req.user,
		section: 'index'
	})
})

app.get("/signup", (req, res, next) => {
	res.render("base", {
		section: 'signup'
	});
});

app.post("/signup", (req, res, next) => {
	const username = req.body.username;
	const password = req.body.password;

	if (username === "" || password === "") {
		res.render("auth/signup", {
			message: "Indicate username and password",
			"section": "private"
		});
		return;
	}

	User.findOne({
			username
		})
		.then(user => {
			if (user !== null) {
				res.render("base", {
					message: "The username already exists",
					"section": "signup"
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
					res.render("base", {
						message: "Something went wrong",
						"section": "signup"
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

app.get("/login", (req, res, next) => {
	res.render("base", {
		"message": req.flash("error"),
		"section": "login"
	});
});

app.post("/login", passport.authenticate("local", {
	successReturnToOrRedirect: "/",
	failureRedirect: "/login",
	failureFlash: true,
	passReqToCallback: true
}));

app.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
	res.render("base", {
		user: req.user,
		"section": "private"
	});
});

app.get("/logout", (req, res) => {
	req.logout();
	res.redirect("/login");
});

app.listen(3000)