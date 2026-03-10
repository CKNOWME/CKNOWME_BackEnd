import express, { Request, Response } from "express";
import { Cert } from "../DB/cert.ts";
import { User } from "../DB/user.ts";
import { getuserJWT } from "../auth.ts";
import { userIpRateLimiter } from "../security.ts";

const router = express.Router();

router.use(userIpRateLimiter);

const parseDate = (value: unknown): number | null => {
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return parsed;
  }
  return null;
};

const resolveAuthUser = async (req: Request): Promise<string | null> => {
  const jwt = req.cookies?.bearer;
  if (!jwt) return null;
  const username = await getuserJWT(jwt);
  if (username === "error") return null;
  return username;
};

router.post("/add", async (req: Request, res: Response) => {
  try {
    const username = await resolveAuthUser(req);
    if (!username) {
      return res.status(401).json({ error: "Please login again" });
    }
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "Please login again" });
    }

    const { title, issuer, description, date, photo, pdfUrl, verifyUrl, category } = req.body ?? {};
    if (!title || !issuer || date == null) {
      return res.status(400).json({ error: "Missing Params" });
    }
    const parsedDate = parseDate(date);
    if (parsedDate == null) {
      return res.status(400).json({ error: "Invalid date" });
    }

    const cert_id = crypto.randomUUID();
    const cert = new Cert({
      id: cert_id,
      title,
      issuer,
      description: description ?? "",
      date: parsedDate,
      photo: photo ?? "",
      pdfUrl: pdfUrl ?? "",
      verifyUrl: verifyUrl ?? "",
      category: category || "General",
    });

    await cert.save();
    user.certs.push(cert_id);
    await user.save();

    return res.status(200).json({ success: "OK", username, certId: cert.id });
  } catch (_err: Error | any) {
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

router.put("/id/:id", async (req: Request, res: Response) => {
  try {
    const checkAuth = await getuserJWT(req.cookies.bearer);
    if (checkAuth == "error") {
      return res.status(401).json({ error: "Please login again" });
    }
    const user = await User.findOne({ username: checkAuth });
    if (!user) {
      return res.status(401).json({ error: "Please login again" });
    }
    if (!user.certs.includes(req.params.id)) {
      return res.status(403).json({ error: "Forbidden - Not your certificate" });
    }
    const cert = await Cert.findOne({ id: req.params.id });
    if (!cert) {
      return res.status(404).json({ error: "Not found" });
    }

    if (req.body.title !== undefined) cert.title = req.body.title;
    if (req.body.issuer !== undefined) cert.issuer = req.body.issuer;
    if (req.body.description !== undefined) cert.description = req.body.description;
    if (req.body.date !== undefined) {
      const parsedDate = parseDate(req.body.date);
      if (parsedDate == null) {
        return res.status(400).json({ error: "Invalid date" });
      }
      cert.date = parsedDate;
    }
    if (req.body.photo !== undefined) cert.photo = req.body.photo;
    if (req.body.pdfUrl !== undefined) cert.pdfUrl = req.body.pdfUrl;
    if (req.body.verifyUrl !== undefined) cert.verifyUrl = req.body.verifyUrl;
    if (req.body.category !== undefined) cert.category = req.body.category;

    await cert.save();
    return res.status(200).json({ success: "OK", certId: cert.id });
  } catch (_err: Error | any) {
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

router.get("/id/:id", async (req: Request, res: Response) => {
  try {
    const cert = await Cert.findOne({ id: req.params.id }).select("-__v -_id");
    if (!cert) {
      return res.status(404).json({ error: "Not found" });
    }
    return res.status(200).json({ success: "OK", cert });
  } catch (_err: Error | any) {
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

router.delete("/id/:id", async (req: Request, res: Response) => {
  try {
    const checkAuth = await getuserJWT(req.cookies.bearer);
    if (checkAuth == "error") {
      return res.status(401).json({ error: "Please login again" });
    }
    const user = await User.findOne({ username: checkAuth });
    if (!user) {
      return res.status(401).json({ error: "Please login again" });
    }
    if (!user.certs.includes(req.params.id)) {
      return res.status(403).json({ error: "Forbidden - Not your certificate" });
    }
    const cert = await Cert.findOneAndDelete({ id: req.params.id });
    if (!cert) {
      return res.status(404).json({ error: "Not found" });
    }
    await User.updateMany(
      { certs: cert.id },
      { $pull: { certs: cert.id } },
    );
    return res.status(200).json({ success: "OK", certId: cert.id });
  } catch (_err: Error | any) {
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

router.get("/all", async (req: Request, res: Response) => {
  try {
    const checkAuth = await getuserJWT(req.cookies.bearer);
    if (checkAuth == "error") {
      return res.status(401).json({ error: "Please login again" });
    }
    const user = await User.findOne({ username: checkAuth });
    if (!user) {
      return res.status(401).json({ error: "Please login again" });
    }
    const userCerts = user.certs;
    const certs = await Cert.find({ id: { $in: userCerts } })
      .select("-__v -_id");
    return res.status(200).json({ success: "OK", certs });
  } catch (_err: Error | any) {
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

export default router;
