const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  let { username, password, role_name } = req.body;
  const hash = bcrypt.hashSync(password, 8);
  const hashedPassword = hash;

  const newUser = await Users.add({
    username: username,
    password: hashedPassword,
    role_name: role_name
  })
  res.status(201).json(newUser)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  try {
  let { username, password } = req.body;
  const user = Users.findBy({ username })
  if(!bcrypt.compareSync(password, user.password)) return res.status(400).json({message: "invalid credentials"})
  const token = jwt.sign({subject: user.id, username: user.username, role_name: user.role_name}, JWT_SECRET, { expiresIn: '1d'})
  res.status(200).json({message: `${username} is back!`, token: token})
  }
  catch {
    res.status(500).json({message: "An error occurred when logging in"})
  }
});

module.exports = router;
