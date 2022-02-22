const router = require('express').Router();
const bcrypt = require('bcryptjs');
const User = require('../users/users-model');

const { checkUsernameFree, checkPasswordLength, checkUsernameExists } = require('./auth-middleware');

router.post('/register', checkUsernameFree, checkPasswordLength, (req, res, next) => {
    const { username, password } = req.body;
    const passwordHash = bcrypt.hashSync(password, 8);
    User.add({ username, password: passwordHash })
        .then((addedUser) => {
            res.status(200).json(addedUser);
        })
        .catch(next);
});

router.post('/login', checkUsernameExists, (req, res, next) => {
  const { password } = req.body;
  if (bcrypt.compareSync(password, req.user.password)) {
        req.session.user = req.user;
        res.status(200).json({ message: `Welcome ${req.user.username}!` });
    } else {
        next({ status: 401, message: 'Invalid credentials' });
    }
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

router.get('/logout', (req, res, next) => {
    if (req.session.user) {
      req.session.destroy(err => {
        if (err) {
          next(err)
        } else {
          res.json({ message: 'logged out' });
        }
      })
    } else {
      res.json({ message: 'no session' });
    }
});

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
