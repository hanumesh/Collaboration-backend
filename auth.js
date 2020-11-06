const jwt = require("jsonwebtoken");

const winstonLogger = require("./winstonLogger");

//Auth Middleware is used to verify the token and retrieve the user based on the token payload
//Used in /getUserInfo to get the information of a user based on the Token ID

module.exports = function(req, res, next) { //In this middleware function, "next" allows the next route handler in line to handle the request
  const token = req.header("token");
  if (!token) 
    return res.status(401).json({ message: "Error in Authentication" });

  try {
    const decoded = jwt.verify(token, "raunakMokhasi");
    req.user = decoded.user;
    next();
  } 
  catch (err) {
    console.error(err);
    winstonLogger.log('error', new Error(err));
    res.status(500).send({ message: "Invalid Token" });
  } 
};