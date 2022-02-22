const User = require('../users/users-model');

function restricted(req, res, next) {
    if (req.session.user) {
        next();
    } else {
      next({ status: 401, message: 'You shall not pass!' });
    }
}

async function checkUsernameFree(req, res, next) {
    try {
        const user = await User.findBy({ username: req.body.username }).first();
        if (user) {
            next({ status: 422, message: 'Username taken' });
        } else {
            next();
        }
    } catch (err) {
        next(err);
    }
}

async function checkUsernameExists(req, res, next) {
    try {
      const user = await User.findBy({ username: req.body.username });
      if (user.length) {
        req.user = user[0];
        next();
      } else {
        next({ status: 401, message: 'Invalid credentials -middle' });
      }
  } catch (err) {
      next(err);
  }
}

function checkPasswordLength(req, res, next) {
    if (!req.body.password || req.body.password.length <= 3) {
        next({ status: 422, message: 'Password must be longer than 3 chars' });
    } else {
        next();
    }
}

module.exports = {
    restricted,
    checkUsernameFree,
    checkUsernameExists,
    checkPasswordLength,
};
