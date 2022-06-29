// routes/auth.routes.js

const { Router } = require('express');
const router = new Router();
const bcryptjs = require('bcryptjs');
const saltRounds = 10;
const User = require('../models/User.model');
 

// GET route ==> to display the signup form to users
router.get("/signup", (req, res, next) => {
    res.render("auth/signup");
  });

// POST route ==> to process form data
router.post('/signup', (req, res, next) => {
    //console.log('The form data: ', req.body);
    const { username, password } = req.body;

    // make sure users fill all mandatory fields:
    if (!username || !password) {
    res.render('auth/signup', { errorMessage: 'All fields are mandatory. Please provide your username and password.' });
    return;
  }
    
    bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      //console.log(`Password hash: ${hashedPassword}`);
      return User.create({
        username, 
        passwordHash: hashedPassword
      });
    })
    .then(userFromDB => {
        //console.log('Newly created user is: ', userFromDB);
        res.redirect('/userProfile');

    })
    .catch(error => {
        // copy the following if-else statement
    if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render('auth/signup', { errorMessage: error.message });
    } else {
        next(error);
    }
  });
})

router.get('/userProfile', (req, res) => res.render('users/user-profile'));

router.get('/login', (req, res) => res.render('auth/login'));

router.post('/login', (req, res, next) => {
    console.log('SESSION =====> ', req.session);
    const { username, password } = req.body;
   
    if (username === '' || password === '') {
      res.render('auth/login', {
        errorMessage: 'Please enter both, username and password to login.'
      });
      return;
    }
   
    User.findOne({ username })
      .then(user => {
        if (!user) {
          res.render('auth/login', { errorMessage: 'This user is not registered. Try with other one.' });
          return;
        } else if (bcryptjs.compareSync(password, user.passwordHash)) {
          //res.render('users/user-profile', { user });
          req.session.currentUser = user;
          res.redirect('/userProfile');
        } else {
          res.render('auth/login', { errorMessage: 'Incorrect password.' });
        }
      })
      .catch(error => next(error));
  });

  router.get('/userProfile', (req, res) => {
    res.render('users/user-profile', { userInSession: req.session.currentUser });
  });

  router.post('/logout', (req, res, next) => {
    req.session.destroy(err => {
      if (err) next(err);
      res.redirect('/');
    });
  });
 
module.exports = router;
