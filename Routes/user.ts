import express, { Request, Response } from "express";
import bcrypt from "bcryptjs";
import { User } from "../DB/user.ts";
import { Cert } from "../DB/cert.ts";
import { createJWT, getuserJWT } from "../auth.ts";
import { authRateLimiter, userIpRateLimiter } from "../security.ts";

const router = express.Router();

const MAX_LOGIN_ATTEMPTS = 5;


const buildAuthCookie = (token: string): string => {
  
  return `bearer=${token}; Path=/; SameSite=Lax; Max-Age=3600; HttpOnly; Secure`;
};
const clearAuthCookie = (): string => {
  return `bearer=; Path=/; SameSite=Lax; Max-Age=0; HttpOnly; Secure`;
};
const buildCsrfCookie = (token: string): string => {
  return `csrf=${token}; Path=/; SameSite=Lax; Max-Age=3600; Secure`;
};
const isEmailValid = (email: string): boolean => {
  return email.includes("@") && email.includes(".");
};


router.get("/csrf", (_req: Request, res: Response) => {
  const token = crypto.randomUUID();
  return res
    .set({ "Set-Cookie": buildCsrfCookie(token) })
    .status(200)
    .json({ csrf: token });
});

router.post("/register", authRateLimiter, async (req: Request, res: Response) => {
  try {
    const { name, username, email, password, photo } = req.body ?? {};
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
      photo: photo || "",
      intentos: MAX_LOGIN_ATTEMPTS,
    });
    await user.save();

    const token = await createJWT({ username: user.username });
    return res
      .set({ "Set-Cookie": buildAuthCookie(token) })
      .status(200)
      .json({ success: "OK", username: user.username });
  } catch (_err: Error | any) {
    return res.status(500).json({ error: "Internal Server Error" });
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
  } catch (_err: Error | any) {
    return res.status(500).json({ error: "Internal Server Error" });
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
  } catch (_err: Error | any) {
    return res.status(500).json({ error: "Internal Server Error" });
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

    const { name, email, photo } = req.body ?? {};
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
    if (photo !== undefined) user.photo = photo;

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
  } catch (_err: Error | any) {
    return res.status(500).json({ error: "Internal Server Error" });
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
  } catch (_err: Error | any) {
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

export default router;
