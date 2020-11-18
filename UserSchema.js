const mongoose = require("mongoose");
const jwt=require('jsonwebtoken');

const UserSchema = mongoose.Schema({
  firstname: { type: String, required: true, maxlength: 100 },
  lastname: { type: String, required: true, maxlength: 100 },
  username: { type: String },
  email: { type: String, required: true, trim: true, unique: 1 },
  password: { type: String, required: true },
  token: { type: String },
  createdAt: { type: Date, default: Date.now() }
});

// generate token 
const SECRET = 'mysecretkey';

UserSchema.methods.generateToken = function (cb) {
  var user = this;

  const payload = {
    user: {
      id: user._id,
      firstname: user.firstname,
      lastname: user.lastname
    }
  };
  
  var token = jwt.sign(payload, SECRET,{expiresIn: '30d' });

  user.token = token;
  user.save(function (err, user) {
    if (err) return cb(err);
    cb(null, user);
  })
}

// find by token
UserSchema.statics.findByToken = function (token, cb) {
  var user = this;

  jwt.verify(token, SECRET, function (err, decode) {
    user.findOne({ "_id": decode, "token": token }, function (err, user) {
      if (err) return cb(err);
      cb(null, user);
    })
  })
};

//delete token

UserSchema.methods.deleteToken = function (token, cb) {
  var user = this;

  user.update({ $unset: { token: 1 } }, function (err, user) {
    if (err) return cb(err);
    cb(null, user);
  })
}


module.exports = mongoose.model("UserSchema", UserSchema);
