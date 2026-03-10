import express, { Request, Response } from "express";
import bcrypt from "bcryptjs";
import multer from "multer";
import { User } from "../DB/user.ts";
import { Cert } from "../DB/cert.ts";
import { createJWT, getuserJWT } from "../auth.ts";
import { authRateLimiter, userIpRateLimiter } from "../security.ts";

const router = express.Router();

const MAX_LOGIN_ATTEMPTS = 5;
const MAX_PHOTO_SIZE = 2 * 1024 * 1024; // 2MB
const ALLOWED_MIME = ["image/png", "image/jpeg", "image/jpg"];
const isProd = Deno.env.get("NODE_ENV") === "production";

const buildAuthCookie = (token: string): string => {
  const secure = isProd ? "; Secure" : "";
  return `bearer=${token}; Path=/; SameSite=Lax; Max-Age=3600; HttpOnly${secure}`;
};
const clearAuthCookie = (): string => {
  const secure = isProd ? "; Secure" : "";
  return `bearer=; Path=/; SameSite=Lax; Max-Age=0; HttpOnly${secure}`;
};
const buildCsrfCookie = (token: string): string => {
  const secure = isProd ? "; Secure" : "";
  return `csrf=${token}; Path=/; SameSite=Lax; Max-Age=3600${secure}`;
};

const isEmailValid = (email: string): boolean => {
  return email.includes("@") && email.includes(".");
};

const isValidImageBuffer = (buffer: Uint8Array, mime: string): boolean => {
  if (mime === "image/png") {
    return buffer.length >= 8 &&
      buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47 &&
      buffer[4] === 0x0d && buffer[5] === 0x0a && buffer[6] === 0x1a && buffer[7] === 0x0a;
  }
  if (mime === "image/jpeg" || mime === "image/jpg") {
    return buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  }
  return false;
};

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_PHOTO_SIZE },
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_MIME.includes(file.mimetype)) {
      return cb(new Error("Invalid file type"));
    }
    cb(null, true);
  },
});

router.get("/csrf", (_req: Request, res: Response) => {
  const token = crypto.randomUUID();
  return res
    .set({ "Set-Cookie": buildCsrfCookie(token) })
    .status(200)
    .json({ csrf: token });
});

router.post("/register", authRateLimiter, async (req: Request, res: Response) => {
  try {
    const { name, username, email, password } = req.body ?? {};
    if (!name || !username || !email || !password) {
      return res.status(400).json({ error: "Missing Params" });
    }
    if (!isEmailValid(email.toString())) {
      return res.status(400).json({ error: "El email es invalido" });
    }

    const existing = await User.findOne({
      $or: [{ username }, { email }],
    });
    if (existing) {
      return res.status(409).json({ error: "Usuario o email ya registrado" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      id: crypto.randomUUID(),
      username,
      name,
      email,
      password: hashedPassword,
      photo: "",
      intentos: MAX_LOGIN_ATTEMPTS,
    });
    await user.save();

    const token = await createJWT({ username: user.username });
    return res
      .set({ "Set-Cookie": buildAuthCookie(token) })
      .status(200)
      .json({ success: "OK", username: user.username });
  } catch (err: Error | any) {
    console.error("Register error:", err);
    if (err?.code === 11000) {
      return res.status(409).json({ error: "Usuario o email ya registrado" });
    }
    return res.status(500).json({
      error: "Internal Server Error",
      detail: isProd ? undefined : (err?.message || String(err)),
    });
  }
});

router.post("/login", authRateLimiter, async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body ?? {};
    if (!username || !password) {
      return res.status(400).json({ error: "Missing params" });
    }
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "Not found" });
    }

    if (!await bcrypt.compare(password, user.password)) {
      user.intentos = Math.max(0, user.intentos - 1);
      await user.save();
      if (user.intentos <= 0) {
        return res.status(429).json({ error: "Anti-BruteForce Triggered" });
      }
      return res.status(401).json({ error: "Bad credentials" });
    }

    user.intentos = MAX_LOGIN_ATTEMPTS;
    await user.save();

    const token = await createJWT({ username: user.username });
    return res
      .set({ "Set-Cookie": buildAuthCookie(token) })
      .status(200)
      .json({ success: "OK", username: user.username });
  } catch (err: Error | any) {
    console.error("Login error:", err);
    return res.status(500).json({
      error: "Internal Server Error",
      detail: isProd ? undefined : (err?.message || String(err)),
    });
  }
});

router.post("/logout", userIpRateLimiter, async (_req: Request, res: Response) => {
  return res
    .set({ "Set-Cookie": clearAuthCookie() })
    .status(200)
    .json({ success: "OK" });
});

router.post("/me", userIpRateLimiter, async (req: Request, res: Response) => {
  try {
    const checkAuth = await getuserJWT(req.cookies.bearer);
    if (checkAuth == "error") {
      return res.status(401).json({ error: "Please login again" });
    }
    const user = await User.findOne({ username: checkAuth });
    if (!user) {
      return res.status(404).json({ error: "Not found" });
    }
    return res.status(200).json({
      user: {
        username: user.username,
        name: user.name,
        email: user.email,
        photo: user.photo,
        certs: user.certs,
      },
    });
  } catch (err: Error | any) {
    console.error("Me error:", err);
    return res.status(500).json({
      error: "Internal Server Error",
      detail: isProd ? undefined : (err?.message || String(err)),
    });
  }
});

router.put("/me", userIpRateLimiter, async (req: Request, res: Response) => {
  try {
    const checkAuth = await getuserJWT(req.cookies.bearer);
    if (checkAuth == "error") {
      return res.status(401).json({ error: "Please login again" });
    }
    const user = await User.findOne({ username: checkAuth });
    if (!user) {
      return res.status(404).json({ error: "Not found" });
    }

    const { name, email } = req.body ?? {};
    if (email && !isEmailValid(email.toString())) {
      return res.status(400).json({ error: "El email es invalido" });
    }

    if (email && email !== user.email) {
      const exists = await User.findOne({ email });
      if (exists) {
        return res.status(409).json({ error: "Email ya registrado" });
      }
      user.email = email;
    }
    if (name) user.name = name;

    await user.save();
    return res.status(200).json({
      success: "OK",
      user: {
        username: user.username,
        name: user.name,
        email: user.email,
        photo: user.photo,
        certs: user.certs,
      },
    });
  } catch (err: Error | any) {
    console.error("Update profile error:", err);
    return res.status(500).json({
      error: "Internal Server Error",
      detail: isProd ? undefined : (err?.message || String(err)),
    });
  }
});

router.post("/me/photo", userIpRateLimiter, upload.single("photo"), async (req: Request, res: Response) => {
  try {
    const checkAuth = await getuserJWT(req.cookies.bearer);
    if (checkAuth == "error") {
      return res.status(401).json({ error: "Please login again" });
    }
    const user = await User.findOne({ username: checkAuth });
    if (!user) {
      return res.status(404).json({ error: "Not found" });
    }

    const file = req.file;
    if (!file || !file.buffer) {
      return res.status(400).json({ error: "Missing file" });
    }
    if (!ALLOWED_MIME.includes(file.mimetype)) {
      return res.status(400).json({ error: "Invalid file type" });
    }
    if (!isValidImageBuffer(file.buffer, file.mimetype)) {
      return res.status(400).json({ error: "Invalid image" });
    }

    const base64 = Buffer.from(file.buffer).toString("base64");
    const dataUrl = `data:${file.mimetype};base64,${base64}`;
    user.photo = dataUrl;
    await user.save();

    return res.status(200).json({ success: "OK", photo: user.photo });
  } catch (err: Error | any) {
    console.error("Upload photo error:", err);
    return res.status(500).json({
      error: "Internal Server Error",
      detail: isProd ? undefined : (err?.message || String(err)),
    });
  }
});

router.get("/:username", async (req: Request, res: Response) => {
  try {
    const username = req.params.username;
    if (!username) {
      return res.status(400).json({ error: "Missing username" });
    }
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "Not found" });
    }
    const certs = await Cert.find({ id: { $in: user.certs } })
      .select("-__v -_id");

    return res.status(200).json({
      user: {
        username: user.username,
        name: user.name,
        photo: user.photo,
        certs,
      },
    });
  } catch (err: Error | any) {
    console.error("Public user error:", err);
    return res.status(500).json({
      error: "Internal Server Error",
      detail: isProd ? undefined : (err?.message || String(err)),
    });
  }
});

export default router;
