const jwt = require("jsonwebtoken");
const User = require('./UserSchema');
const winstonLogger = require("./winstonLogger");
//Auth Middleware is used to verify the token and retrieve the user based on the token payload
//Used in /getUserInfo to get the information of a user based on the Token ID

// module.exports = function (req, res, next) { //In this middleware function, "next" allows the next route handler in line to handle the request
//   const token = req.header("token");
//   if (!token)
//     return res.status(401).json({ message: "Error in Authentication" });

//   try {
//     const decoded = jwt.verify(token, "hanumesh");
//     req.user = decoded.user;
//     next();
//   }
//   catch (err) {
//     console.error(err);
//     winstonLogger.log('error', new Error(err));
//     res.status(500).send({ message: "Invalid Token" });
//   }
// };


let auth = (req, res, next) => {
  let token = req.header("token");
  User.findByToken(token, (err, user) => {
    if (err) throw err;
    if (!user) return res.json({
      error: true
    });

    req.token = token;
    req.user = user;
    next();

  })
}

module.exports = { auth };