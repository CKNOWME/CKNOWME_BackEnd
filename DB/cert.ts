import mongoose from "mongoose";

export const certSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  title: { type: String, required: true },
  issuer: { type: String, required: true },
  description: { type: String, required: true },
  date: { type: Number, required: true },
  pdfUrl: { type: String, required: true },
  verifyUrl: { type: String, required: true },
  category: { type: String, required: true },
});

export const Cert = mongoose.model("CvCerts", certSchema);