if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
};



const path = require('path');
const bcrypt = require('bcrypt');
const mysql = require('mysql');
const hbs = require('hbs');
const passport = require('passport');
const express = require('express');
const flash = require('express-flash');
const session = require('express-session');
const util = require('util');

const initPassport = require('./passport-config');
const pageCont = require('./cont/cont.json');
const subpages = require('./cont/pages.json');



const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PSW,
    database: process.env.DB
});

const query = util.promisify(db.query).bind(db);



initPassport(
    passport,
    async (email) => { return (await query(`SELECT id, name, email, password FROM users WHERE email = ?`, [email]))[0] },
    async (id) => { return (await query(`SELECT id, name, email, password FROM users WHERE id = ?`, [id]))[0] }
);


const app = express();





hbs.registerPartials(__dirname + '/views/partials');

app.set('view engine', 'hbs');




app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.enable('view cache');





app.get('/login', checkNotAuth, (req, res) => {
    let cont = pageCont;

    cont.pageName = 'Login';

    res.render('login', cont);
});

app.get('/register', checkNotAuth, (req, res) => {
    let cont = pageCont;

    cont.pageName = 'Register';

    res.render('register', cont);
});

app.get('/profile', checkAuth, (req, res) => {
    let cont = pageCont;

    cont.pageName = 'Profile';

    cont.userName = req.user.name;
    cont.userEmail = req.user.email;

    res.render('profile', cont);
});

for (let i = 0; i < subpages.pageNames.length; i++) {
    app.get(subpages.pageNames[i].subjLink, (req, res) => {
        let cont = pageCont;

        cont.pageName = subpages.pageNames[i].subjName;
        cont.userName = req.user?.name;

        res.render(subpages.pageNames[i].pageTemp, cont);
    });
};

app.get('*', (req, res) => {
    res.status(404).redirect('/');
});




app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));

app.post('/register', async (req, res) => {
    const { email, name, password, passwordConfirm } = req.body;

    let cont = pageCont;

    let results = await query(`SELECT email FROM users WHERE email = ?`, [email]);

    let valPass = validatePassword(password, passwordConfirm);
    let valEmail = validateEmail(email);
    let valName = validateName(name);

    if (results.length > 0 || valEmail || valPass || valName) {
        cont.pageName = 'Register';

        if (results.length > 0) {
            cont.message = 'The email is already in use';
        }
        else if (valEmail) {
            cont.message = valEmail;
        }
        else if (valPass) {
            cont.message = valPass;
        }
        else if (valName) {
            cont.message = valName;
        }

        res.render('register', cont);
    }
    else {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        db.query(`INSERT INTO users SET ?`, { name, email, password: hashedPassword }, (err) => {
            if (err) { console.log(err); return };

            cont.pageName = 'Registration successfull';
            cont.userNameReg = name;
            cont.userEmailReg = email;

            res.render('registerSucc', cont);
        });
    }

    cont.message = undefined;
    cont.userNameReg = undefined;
    cont.userEmailReg = undefined;
});

app.post('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
});

app.post('/saveProf', checkAuth, async (req, res) => {
    const { email, name } = req.body;

    let cont = pageCont;

    let results = await query(`SELECT id FROM users WHERE email = ?`, [email]);

    let valEmail = validateEmail(email);
    let valName = validateName(name);

    if (results.length > 0 && results[0].id !== req.user.id || valEmail || valName) {
        cont.pageName = 'Profile';

        if (results.length > 1) {
            cont.message = 'Email validation error';
        }
        else if (results.length > 0 && results[0].id !== req.user.id) {
            cont.message = 'The email is already in use';
        }
        else if (valEmail) {
            cont.message = valEmail;
        }
        else if (valName) {
            cont.message = valName;
        }

        res.render('profile', cont);
    }
    else {
        db.query(`UPDATE users SET ? WHERE id = ${req.user.id}`, { name, email }, (err) => {
            if (err) { console.log(err); return };

            cont.pageName = 'Account change successfull';
            cont.userNameReg = name;
            cont.userEmailReg = email;

            res.render('registerSucc', cont);
        })
    }

    cont.message = undefined;
    cont.userNameReg = undefined;
    cont.userEmailReg = undefined;
});

app.post('/savePass', checkAuth, async (req, res) => {
    const { password, passwordConfirm } = req.body;

    let cont = pageCont;

    let valPass = validatePassword(password, passwordConfirm);

    if (valPass) {
        cont.pageName = 'Profile';

        cont.messagePass = valPass;

        res.render('profile', cont);
    }
    else {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        db.query(`UPDATE users SET ? WHERE id = ${req.user.id}`, { password: hashedPassword }, (err) => {
            if (err) { console.log(err); return };

            cont.pageName = 'Password change successfull';

            res.render('registerSucc', cont);
        })
    }

    cont.message = undefined;
});




function checkAuth(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    };

    res.redirect('/login');
};


function checkNotAuth(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    };

    next();
}


function validatePassword(pass, passConf) {
    if (pass.length < 8 || pass !== passConf) {
        if (pass.length < 8) {
            return 'Password is too short';
        }
        else if (pass !== passConf) {
            return 'Passwords do not match';
        };
    };
    return false;
}


function validateEmail(email) {
    if (email.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/) === null) {
        cont.message = 'This email does not exist';
    };
    return false;
}


function validateName(name) {
    if (name.length < 3) {
        cont.message = 'Name is too short';
    };
    return false;
}



app.listen(3000);