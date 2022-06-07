var express = require('express');
var router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const secretKey = "SUPER SECRET KEY DO NOT STEAL";

/* GET home page. */
router.get('/', function (req, res, next) {
  res.render('index', { title: 'The World Database API' });
});

router.get('/api', function (req, res, next) {
  res.render('index', { title: 'Lots of routes available' });
});

router.get('/api/city', function (req, res, next) {
  req.db.from('City').select('name', 'district')
    .then(
      rows => {
        res.status(200).json({
          Error: false,
          Message: "success",
          City: rows
        })
      }
    )
    .catch(err => {
      console.log(err);
      res.status(500).json({
        Error: true,
        Message: "Error in MySQL query"
      })
    });
});


router.get('/api/city/:CountryCode', function (req, res, next) {
  const countryCode = req.params.CountryCode;

  req.db.from('City').select('*').where('CountryCode', '=', countryCode)
    //req.db.raw(`SELECT * FROM City WHERE CountryCode = '${countryCode}'`)
    .then(
      rows => {
        res.status(200).json({
          Error: false,
          Message: "success",
          Cities: rows
        })
      }
    )
    .catch(err => {
      console.log(err);
      res.status(500).json({
        Error: true,
        Message: "Error in MySQL query"
      })
    });
});

const authorize = function (req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || auth.split(" ").length !== 2) {
    res.status(401).json({
      Error: true,
      Message: "Missing or malformed JWT"
    });
    return;
  }
  const token = auth.split(" ")[1];
  try {
    const payload = jwt.verify(token, secretKey);
    if (Date.now() > payload.exp) {
      res.status(401).json({
        Error: true,
        Message: "Expired JWT"
      });
      return;
    }

    next();
  } catch (e) {
    res.status(401).json({
      Error: true,
      Message: "Invalid JWT"
    });
    return;
  }
};

router.post('/api/update', authorize, function (req, res, next) {
  if (!req.body.City || !req.body.CountryCode || !req.body.Pop) {
    res.status(400).json({ Error: true, Message: "Missing parameter" });
    return;
  }
  req.db.from('City').update({ 'Population': req.body.Pop }).where({ 'CountryCode': req.body.CountryCode, 'Name': req.body.City })
    .then(() => res.status(200).json({
      Error: false,
      Message: `Updated population of ${req.body.City} to ${req.body.Pop}`
    }))
    .catch(err => {
      console.log(err);
      res.status(500).json({
        Error: true,
        Message: "Error in MySQL query"
      })
    });

  //res.send(JSON.stringify(req.body));

});


router.post('/register', function (req, res, next) {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({
      Error: true,
      Message: "Request body incomplete, both email and password are required"
    });
    return;
  }
  if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
    res.status(400).json({
      Error: true,
      Message: "Invalid format email address"
    });
    return;
  }

  req.db.from("Users").select("*").where({ email })
    .then(users => {
      if (users.length > 0) {
        res.status(409).json({
          Error: true,
          Message: "Email already in use"
        });
        return;
      }

      const hash = bcrypt.hashSync(password, 10);
      req.db.from("Users").insert({ email, hash })
        .then(() => {
          res.status(200).json({
            Error: false,
            Message: "User created"
          });
        })
        .catch(err => {
          console.log(err);
          res.status(500).json({
            Error: true,
            Message: "Error in MySQL query"
          })
        });
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({
        Error: true,
        Message: "Error in MySQL query"
      })
    });
});

router.post('/login', function (req, res, next) {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({
      Error: true,
      Message: "Request body incomplete, both email and password are required"
    });
    return;
  }
  req.db.from("Users").select("*").where({ email })
    .then(users => {
      if (users.length === 0) {
        res.status(400).json({
          Error: true,
          Message: "User not registered"
        });
        return;
      }

      const { hash } = users[0];

      if (!bcrypt.compareSync(password, hash)) {
        res.status(400).json({
          Error: true,
          Message: "Incorrect password"
        });
        return;
      }
      const expires_in = 60 * 60 * 24;

      const exp = Date.now() + expires_in * 1000;
      const token = jwt.sign({ email, exp }, secretKey);

      res.status(200).json({ 
        token,
        token_type: "Bearer",
        expires_in
      });
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({
        Error: true,
        Message: "Error in MySQL query"
      })
    });
});

module.exports = router;
