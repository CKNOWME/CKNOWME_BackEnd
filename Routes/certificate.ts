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

const PRIVATE_IPS = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
  /^::1$/,
  /^localhost$/i,
];
const PRIVATE_IP_RANGES = [/^172\.(1[6-9]|2\d|3[0-1])\./];

const isPrivateHost = (hostname: string): boolean => {
  return PRIVATE_IPS.some((rule) => rule.test(hostname)) ||
    PRIVATE_IP_RANGES.some((rule) => rule.test(hostname));
};

const validatePublicUrl = (rawUrl: string): boolean => {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
    if (isPrivateHost(parsed.hostname)) return false;
    if (parsed.hostname.endsWith(".local")) return false;
    return true;
  } catch {
    return false;
  }
};

const normalizeOptionalUrl = (value: unknown): string => {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  if (!trimmed) return "";
  return trimmed;
};

const ensureSafeUrls = (urls: string[]): boolean => {
  for (const url of urls) {
    if (!url) continue;
    if (!validatePublicUrl(url)) return false;
  }
  return true;
};

const normalizeTags = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    return value
      .map((v) => (typeof v === "string" ? v.trim() : ""))
      .filter((v) => v.length > 0)
      .slice(0, 12);
  }
  if (typeof value === "string") {
    return value.split(",").map((v) => v.trim()).filter(Boolean).slice(0, 12);
  }
  return [];
};

const normalizeHash = (value: unknown): string => {
  if (typeof value !== "string") return "";
  const cleaned = value.trim().toLowerCase();
  if (!cleaned) return "";
  if (!/^[a-f0-9]{64}$/.test(cleaned)) return "";
  return cleaned;
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

    const { title, issuer, description, date, photo, pdfUrl, verifyUrl, category, isPublic, tags, hash, expiresAt } = req.body ?? {};
    if (!title || !issuer || date == null) {
      return res.status(400).json({ error: "Missing Params" });
    }
    const parsedDate = parseDate(date);
    if (parsedDate == null) {
      return res.status(400).json({ error: "Invalid date" });
    }

    const photoUrl = normalizeOptionalUrl(photo);
    const pdf = normalizeOptionalUrl(pdfUrl);
    const verify = normalizeOptionalUrl(verifyUrl);

    if (!ensureSafeUrls([photoUrl, pdf, verify])) {
      return res.status(400).json({ error: "Invalid URL" });
    }

    const cert_id = crypto.randomUUID();
    const cert = new Cert({
      id: cert_id,
      title,
      issuer,
      description: description ?? "",
      date: parsedDate,
      photo: photoUrl,
      pdfUrl: pdf,
      verifyUrl: verify,
      category: (typeof category === "string" && category.trim()) ? category.trim() : "General",
      isPublic: typeof isPublic === "boolean" ? isPublic : true,
      tags: normalizeTags(tags),
      hash: normalizeHash(hash),
      expiresAt: parseDate(expiresAt) ?? undefined,
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

    const photoUrl = req.body.photo !== undefined ? normalizeOptionalUrl(req.body.photo) : cert.photo;
    const pdf = req.body.pdfUrl !== undefined ? normalizeOptionalUrl(req.body.pdfUrl) : cert.pdfUrl;
    const verify = req.body.verifyUrl !== undefined ? normalizeOptionalUrl(req.body.verifyUrl) : cert.verifyUrl;
    if (!ensureSafeUrls([photoUrl, pdf, verify])) {
      return res.status(400).json({ error: "Invalid URL" });
    }
    cert.photo = photoUrl;
    cert.pdfUrl = pdf;
    cert.verifyUrl = verify;

    if (req.body.category !== undefined) {
      cert.category = typeof req.body.category === "string" && req.body.category.trim()
        ? req.body.category.trim()
        : cert.category;
    }

    if (req.body.isPublic !== undefined) cert.isPublic = Boolean(req.body.isPublic);
    if (req.body.tags !== undefined) cert.tags = normalizeTags(req.body.tags);
    if (req.body.hash !== undefined) cert.hash = normalizeHash(req.body.hash);
    if (req.body.expiresAt !== undefined) {
      cert.expiresAt = parseDate(req.body.expiresAt) ?? cert.expiresAt;
    }

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
