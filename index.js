require("./utils.js");

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require("joi");

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 12;
const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory stor
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        var notLogged = `<a href="/signup"><button>Sign Up</button></a> <br>
        <a href="/login"><button>Login</button></a>`;
        res.send(notLogged);
    } else {
        var Logged = `
        Hello, ${req.session.name}! <br>
        <a href="/members"><button>Go to Members Area</button></a> <br>
        <a href="/logout"><button>Logout</button></a>
        `;
        res.send(Logged);
    }
});

app.get('/signup', (req, res) => {

    var missingName = req.query.missingname;
    var missingEmail = req.query.missingemail;
    var missingPassword = req.query.missingpassword;

    var signup = `
    create user
    <form action='/signingup' method='post'>
    <input name='name' type='text' placeholder='name'> <br>
    <input name='email' type='text' placeholder='email'> <br>
    <input name='password' type='password' placeholder='password'> <br>
    <button>Submit</button>
    </form>
    `;

    if (missingName) {
        signup += "<br> name is required";
    }
    if (missingEmail) {
        signup += "<br> email is required";
    }
    if (missingPassword) {
        signup += "<br> password is required";
    }

    res.send(signup);
});

app.post('/signingup', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    var redirect = "/signup?";

    if (!name) {
        redirect += 'missingname=1';
    }
    if (!email) {
        if(!name) {
            redirect += "&";
        }
        redirect += 'missingemail=1';
    }
    if (!password) {
        if(!name || !email) {
            redirect += "&";
        }
        redirect += 'missingpassword=1';
    }

    if (!name || !email || !password) {
        res.redirect(redirect);
    }
    else {

        const schema = Joi.object(
            {
                name: Joi.string().max(20).required(),
                email: Joi.string().email().required(),
                password: Joi.string().max(20).required()
            });
        
        const validationResult = schema.validate({name, email, password});
        if (validationResult.error != null) {
           console.log(validationResult.error);
           res.redirect("/signup");
           return;
       }
    
        var hashedPassword = await bcrypt.hash(password, saltRounds);
        
        await userCollection.insertOne({name:name, email: email, password: hashedPassword});
        console.log("Inserted user");

        req.session.authenticated = true;
		req.session.email = email;
        req.session.name = name;
		req.session.cookie.maxAge = expireTime;

        res.redirect("/members");
    }
});

app.get('/login', (req,res) => {
    if (!req.session.authenticated) {
        var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'> <br>
    <input name='password' type='password' placeholder='password'> <br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
    } else {
        res.redirect("/");
    }
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().email().required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, password: 1, _id: 1, name: 1}).toArray();

    badLoginHtml = `
    <p>Invalid email/password combination</p> <br>
    <br>
    <a href="/login">Try again</a>   
    `

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
        res.send(badLoginHtml);
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
        req.session.name = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		res.send(badLoginHtml);
		return;
	}
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    } else {

        const randomImageSelector = Math.floor(Math.random() * 3);
        if (randomImageSelector == 1) {
            var image = "/ssm1.jpg";
        } else if (randomImageSelector == 2) {
            var image = "/ssm2.jpg";
        } else {
            var image = "/ssm3.jpg";
        }

        var html = `
        <p>Hello ${req.session.name}</p> <br>
        <img src="${image}"> <br>
        <a href="/logout"><button>Sign out</button></a>
        `;
        res.send(html);
    }
    

});

app.get('/logout', (req, res) => {
    req.session.destroy();
    var html = `
    You are logged out.
    `;
    res.send(html);
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});