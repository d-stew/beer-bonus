var express = require('express');
var router = express.Router();
var knex = require('../db')

/* GET users listing. */
router.post('/signup', function(req, res, next) {
  const errors = [];

  if (!req.body.email || !req.body.email.trim()) errors.push("Email can't be blank");
  if (!req.body.name || !req.body.name.trim()) errors.push("Name can't be blank");
  if (!req.body.password || !req.body.password.trim()) errors.push("Password can't be blank");

  if (errors.length) {
    res.status(422).json({
      errors: errors
    })
  } else {
    knex('users')
    .whereRaw('lower(email) = ?', req.body.email.toLowerCase())
    .count() // [{count: "0"}]
    .first() // {count: "0"}
    .then(function (result) {
      // {count: "0"}
      if (result.count === "0") {
        // We're good
      } else {
        res.status(422).json({
          errors: ["Email has already been taken"]
        })
      }
    })
  }

  // Require knex
  // Check email, name and password are all there
  // If not, return an error
  // Check to see if email already exists in the db
  // If so, return an error
  // If we're okay,
  // Hash password
  // knex insert stuff from req.bodyParser
  // Create a token
  // Send back id, email, name and token
});

module.exports = router;
