const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model')
const jwt = require('jsonwebtoken')


const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */

  const token = req.headers.authorization
  if(!token) return res.status(401).json({message: "Token required"})
  jwt.verify(token, JWT_SECRET, err => {
    if(err) return res.status(401).json({message: "Token invalid"})
    else next()
  })
  next()
  
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
  jwt.verify()
}


const checkUsernameExists = async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
 let { username } = req.body;
  const user = await Users.findBy({ username })
  if(!user) return res.status(401).json({message: "Invalid credentials"})
  next()
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
    let { role_name } = req.body;
    if(!(role_name in req.body) || role_name.trim() === "")
    return role_name = 'student'
    
    if(role_name.trim() === 'admin')
    return res.status(422).json({message: "Role name can not be admin"})

    if(role_name.trim().length > 32)
    return res.status(422).json({message: "Role name can not be longer than 32 chars"})
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
