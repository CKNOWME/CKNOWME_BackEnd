import mongoose from "mongoose";


export const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  username: { type: String, required: true , unique: true},
  name: { type: String, required: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  photo: { type: String, required: true, default: "" },
  certs : {type: [String], required: true, default: []},
  intentos: { type: Number, required: true ,default: 5},
});

export const User = mongoose.model("CvUser", userSchema);