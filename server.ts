import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import userRoutes from "./Routes/user.ts";
import certificateRoutes from "./Routes/certificate.ts";
import oauthRoutes from "./Routes/oauth.ts";
import cookieParser from "cookie-parser";

import {
  apiRateLimiter,
  csrfGuard,
  requestSecurityGuards,
  securityHeaders,
} from "./security.ts";

dotenv.config();

const app = express();
const port = Deno.env.get("PORT") || 3000;
const mongoUri = Deno.env.get("MONGO_URI") || "";

if (!mongoUri) {
  throw new Error("MONGO_URI is missing");
}

app.disable("x-powered-by"); // Disable for black-box
app.use(securityHeaders); // Global security headers
app.use(apiRateLimiter); // Global rate limiter
app.use(express.json());
app.use(cookieParser());
app.use(requestSecurityGuards); // Custom middleware
app.use(csrfGuard); // CSRF for unsafe methods

app.use("/user", userRoutes);
app.use("/certificate", certificateRoutes);
app.use("/oauth", oauthRoutes);

mongoose.connect(mongoUri)
  .then(() => {
    console.log("Conectado a MongoDB");
    app.listen(port, () => console.log(`Servidor en http://localhost:${port}`));
  })
  .catch((err: Error | any) => console.error("Error al conectar a MongoDB:", err));
