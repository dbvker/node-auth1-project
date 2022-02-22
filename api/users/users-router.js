const router = require('express').Router();

const { restricted } = require('../auth/auth-middleware');
const User = require('./users-model');

router.get('/', restricted, (req, res, next) => {
    User.find()
        .then((users) => {
            res.status(200).json(users);
        })
        .catch(next);
});

module.exports = router;
