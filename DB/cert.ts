import mongoose from "mongoose";

export const certSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  title: { type: String, required: true, trim: true },
  issuer: { type: String, required: true, trim: true },
  description: { type: String, required: true, default: "" },
  date: { type: Number, required: true },
  pdfUrl: { type: String, required: true, default: "" },
  verifyUrl: { type: String, required: true, default: "" },
  photo: { type: String, required: true, default: "" },
  category: { type: String, required: true, default: "General" },
  isPublic: { type: Boolean, required: true, default: true },
  tags: { type: [String], required: true, default: [] },
  hash: { type: String, required: false, default: "" },
  expiresAt: { type: Number, required: false },
});

export const Cert = mongoose.model("CvCerts", certSchema);
