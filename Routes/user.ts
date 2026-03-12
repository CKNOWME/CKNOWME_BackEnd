import express, { Request, Response } from "express";
import bcrypt from "bcryptjs";
import { User } from "../DB/user.ts";
import { Cert } from "../DB/cert.ts";
import { createJWT, getuserJWT } from "../auth.ts";
import { authRateLimiter, userIpRateLimiter } from "../security.ts";
import { Buffer } from "node:buffer";
import { upload,uploadCv,isEmailValid,buildCsrfCookie,ALLOWED_MIME,clearAuthCookie,CV_MIME,isValidPdfBuffer,isValidImageBuffer,MAX_LOGIN_ATTEMPTS,buildAuthCookie} from "../util.ts";
const router = express.Router();


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
      cv: "",
      intentos: MAX_LOGIN_ATTEMPTS,
    });
    await user.save();

    const token = await createJWT({ username: user.username });
    return res
      .set({ "Set-Cookie": buildAuthCookie(token) })
      .status(200)
      .json({ success: "OK", username: user.username });
  } catch (err: Error | any) {
    if (err?.code === 11000) {
      return res.status(409).json({ error: "Usuario o email ya registrado" });
    }
    return res.status(500).json({
      error: "Internal Server Error",
      
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
    return res.status(500).json({
      error: "Internal Server Error",
      
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
        cv: user.cv,
        age: user.age,
        studies: user.studies,
        links: user.links,
        certs: user.certs,
      },
    });
  } catch (err: Error | any) {
    return res.status(500).json({
      error: "Internal Server Error",
      
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

    const { name, email, age, studies, links } = req.body ?? {};
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
    if (typeof age === "number") user.age = age;
    if (typeof studies === "string") user.studies = studies;
    if (links && typeof links === "object") {
      user.links = {
        github: typeof links.github === "string" ? links.github : user.links?.github || "",
        portfolio: typeof links.portfolio === "string" ? links.portfolio : user.links?.portfolio || "",
        linkedin: typeof links.linkedin === "string" ? links.linkedin : user.links?.linkedin || "",
        website: typeof links.website === "string" ? links.website : user.links?.website || "",
      };
    }

    await user.save();
    return res.status(200).json({
      success: "OK",
      user: {
        username: user.username,
        name: user.name,
        email: user.email,
        photo: user.photo,
        cv: user.cv,
        age: user.age,
        studies: user.studies,
        links: user.links,
        certs: user.certs,
      },
    });
  } catch (err: Error | any) {
    return res.status(500).json({
      error: "Internal Server Error",
      
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
    return res.status(500).json({
      error: "Internal Server Error",
      
    });
  }
});

router.post("/me/cv", userIpRateLimiter, uploadCv.single("cv"), async (req: Request, res: Response) => {
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
    if (!CV_MIME.includes(file.mimetype)) {
      return res.status(400).json({ error: "Invalid file type" });
    }
    if (!isValidPdfBuffer(file.buffer)) {
      return res.status(400).json({ error: "Invalid PDF" });
    }

    const base64 = Buffer.from(file.buffer).toString("base64");
    const dataUrl = `data:${file.mimetype};base64,${base64}`;
    user.cv = dataUrl;
    await user.save();

    return res.status(200).json({ success: "OK", cv: user.cv });
  } catch (err: Error | any) {
    return res.status(500).json({
      error: "Internal Server Error",
      
    });
  }
});

router.delete("/me/cv", userIpRateLimiter, async (req: Request, res: Response) => {
  try {
    const checkAuth = await getuserJWT(req.cookies.bearer);
    if (checkAuth == "error") {
      return res.status(401).json({ error: "Please login again" });
    }
    const user = await User.findOne({ username: checkAuth });
    if (!user) {
      return res.status(404).json({ error: "Not found" });
    }
    user.cv = "";
    await user.save();
    return res.status(200).json({ success: "OK" });
  } catch (err: Error | any) {
    return res.status(500).json({
      error: "Internal Server Error",
      
    });
  }
});

router.delete("/me/photo", userIpRateLimiter, async (req: Request, res: Response) => {
  try {
    const checkAuth = await getuserJWT(req.cookies.bearer);
    if (checkAuth == "error") {
      return res.status(401).json({ error: "Please login again" });
    }
    const user = await User.findOne({ username: checkAuth });
    if (!user) {
      return res.status(404).json({ error: "Not found" });
    }
    user.photo = "";
    await user.save();
    return res.status(200).json({ success: "OK" });
  } catch (err: Error | any) {
    return res.status(500).json({
      error: "Internal Server Error",
      
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
        cv: user.cv,
        age: user.age,
        studies: user.studies,
        links: user.links,
        certs,
      },
    });
  } catch (err: Error | any) {
    return res.status(500).json({
      error: "Internal Server Error",
      
    });
  }
});

export default router;
