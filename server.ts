import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import userRoutes from "./Routes/user.ts";
import certificateRoutes from "./Routes/certificate.ts";
import cookieParser from "cookie-parser";

import {
  apiRateLimiter,
  requestSecurityGuards,
  securityHeaders,
} from "./security.ts";

dotenv.config();

const app = express();
const port = Deno.env.get("PORT") || 3000;
const mongoUri = Deno.env.get("MONGO_URI") || "";

app.disable("x-powered-by"); // Disable for black-box
app.use(securityHeaders); // Global security headers
app.use(apiRateLimiter); // Global rate limiter
app.use(requestSecurityGuards); // Custom middleware
app.use(express.json());
app.use(cookieParser());


app.use("/user", userRoutes);
app.use("/certificate", certificateRoutes);

mongoose.connect(mongoUri)
  .then(() => {
    console.log("Conectado a MongoDB");
    app.listen(port, () => console.log(`Servidor en http://localhost:${port}`));
  })
  .catch((err:Error | any) => console.error("Error al conectar a MongoDB:", err));