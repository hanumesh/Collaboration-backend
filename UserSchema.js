const mongoose = require("mongoose");

const UserSchema = mongoose.Schema({
  firstname: { type: String, required: true, maxlength: 100 },
  lastname: { type: String, required: true, maxlength: 100 },
  username: { type: String },
  email: { type: String, required: true,  trim: true, unique: 1 },
  password: { type: String, required: true },
  token:{ type: String },
  createdAt: { type: Date, default: Date.now() }
});

module.exports = mongoose.model("UserSchema", UserSchema);
