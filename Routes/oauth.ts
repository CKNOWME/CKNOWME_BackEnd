import express, { Request, Response } from "express";
import multer from "multer";
import { User } from "../DB/user.ts";
import { Cert } from "../DB/cert.ts";
import { userIpRateLimiter } from "../security.ts";
import { CredlyBadge } from "../types.ts";
import {
  resolveAuthUser,
  extractCredlySlug,
  badgeEndpointFor,
  issuerFrom,
  parseDate,
  normalizeTags,
  ensureSafeUrls,
  getCredlyBadges,
  parseLinkedInCertifications,
} from "../util.ts";

const router = express.Router();
router.use(userIpRateLimiter);

const uploadLinkedinHtml = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req: any, file: any, cb: any) => {
    const ok = ["text/html", "application/xhtml+xml"].includes(file.mimetype);
    if (!ok) return cb(new Error("Invalid file type"));
    cb(null, true);
  },
});

router.post("/linkedin/import-html", uploadLinkedinHtml.single("html"), async (req: Request, res: Response) => {
  try {
    const username = await resolveAuthUser(req);
    if (!username) {
      return res.status(401).json({ error: "Please login again" });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "Please login again" });
    }

    const file = req.file;
    if (!file || !file.buffer) {
      return res.status(400).json({ error: "Missing html" });
    }
    const fullHtml = file.buffer.toString("utf-8");
    if (!fullHtml || fullHtml.length < 200) {
      return res.status(400).json({ error: "Empty html" });
    }
    let parsedCerts = [];
    try {
      parsedCerts = parseLinkedInCertifications(fullHtml);
    } catch (_err:Error | unknown) {
      return res.status(500).json({ error: "Internal Server Error" });
    }

    if (parsedCerts.length == 0) {
      return res.status(200).json({ success: "OK", imported: 0, skipped: 0 });
    }

    const mapped = parsedCerts
      .filter((cert) => cert.name && cert.company)
      .map((cert) => {
        const verifyUrl = cert.url || "";
        const pdfUrl = "";
        const photo = cert.image || "";
        const date = cert.issuedAt || Date.now();
        const expiresAt = cert.expiresAt || undefined;
        return {
          verifyUrl,
          data: {
            id: crypto.randomUUID(),
            title: cert.name,
            issuer: cert.company,
            description: "",
            date,
            pdfUrl,
            verifyUrl,
            photo,
            category: "LinkedIn",
            isPublic: true,
            tags: [],
            hash: "",
            expiresAt,
          },
        };
      })
      .filter((item) => ensureSafeUrls([item.verifyUrl, item.data.photo]));

    if (mapped.length == 0) {
      return res.status(200).json({ success: "OK", imported: 0, skipped: parsedCerts.length });
    }

    const verifyUrls = mapped.map((m) => m.verifyUrl).filter(Boolean);
    const existing = await Cert.find({
      id: { $in: user.certs },
      verifyUrl: { $in: verifyUrls },
    }).select("verifyUrl -_id");
    const existingSet = new Set(existing.map((e: { verifyUrl: string }) => e.verifyUrl));

    const toInsert = mapped
      .filter((m) => !m.verifyUrl || !existingSet.has(m.verifyUrl))
      .map((m) => m.data);

    if (toInsert.length === 0) {
      return res.status(200).json({ success: "OK", imported: 0, skipped: mapped.length });
    }

    await Cert.insertMany(toInsert);
    user.certs.push(...toInsert.map((c: { id: string }) => c.id));
    await user.save();

    return res.status(200).json({
      success: "OK",
      imported: toInsert.length,
      skipped: mapped.length - toInsert.length,
    });
  } catch (err:Error | unknown) {
    console.log(err)
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

router.post("/credly/import", async (req: Request, res: Response) => {
  try {
    const username = await resolveAuthUser(req);
    if (!username) {
      return res.status(401).json({ error: "Please login again" });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "Please login again" });
    }

    const rawUrl = req.body?.url ? String(req.body.url).trim() : "";
    if (!rawUrl) {
      return res.status(400).json({ error: "Missing URL" });
    }

    const slug = extractCredlySlug(rawUrl);
    if (!slug) {
      return res.status(400).json({ error: "Invalid Credly URL" });
    }

    const endpoint = badgeEndpointFor(slug);
    const response = await fetch(endpoint, {
      headers: {
        Accept: "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent":
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        "Accept-Language": "es-ES,es;q=0.9",
        "Sec-Ch-Ua": '"Chromium";v="145", "Not:A-Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"macOS"',
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        Referer: `https://www.credly.com/users/${slug}/badges`,
        "Accept-Encoding": "gzip, deflate, br",
        Priority: "u=1, i",
      },
    });

    if (!response.ok) {
      await response.text();
      return res.status(502).json({ error: "Credly import failed" });
    }

    const text = await response.text();
    if (text.trim().startsWith("<")) {
      return res.status(502).json({ error: "Credly import failed" });
    }
    const json = JSON.parse(text);
    const id = json?.data?.synthetic_id ? json.data.synthetic_id : null;
    if (!id) {
      return res.status(502).json({ error: "Credly import failed" });
    }

    const badges: CredlyBadge[] | null = await getCredlyBadges(id);
    if (!badges) {
      return res.status(502).json({ error: "Credly import failed" });
    }

    const mapped = badges
      .map((badge: CredlyBadge): { data: any; verifyUrl: string } | null => {
        const date = parseDate(badge.issued_at_date);
        if (!date) return null;

        const title = badge.badge_template?.name || "Credly Badge";
        const issuer = issuerFrom(badge);
        const description = badge.badge_template?.description || "";
        const photo = badge.badge_template?.image_url || badge.image_url || "";
        const verifyUrl = `https://www.credly.com/badges/${badge.id}`;
        const pdfUrl = `https://www.credly.com/badges/${badge.id}`;
        const category = badge.badge_template?.type_category || "Credly";
        const tags = normalizeTags(badge.badge_template?.skills);
        const expiresAt = parseDate(badge.expires_at_date ?? null) || undefined;
        const isPublic = badge.public !== false;

        if (!ensureSafeUrls([photo, verifyUrl, pdfUrl])) return null;

        return {
          verifyUrl,
          data: {
            id: crypto.randomUUID(),
            title,
            issuer,
            description,
            date,
            pdfUrl,
            verifyUrl,
            photo,
            category,
            isPublic,
            tags,
            hash: "",
            expiresAt,
          },
        };
      })
      .filter(Boolean) as { data: any; verifyUrl: string }[];

    if (mapped.length === 0) {
      return res.status(200).json({ success: "OK", imported: 0, skipped: badges.length });
    }

    const verifyUrls = mapped.map((m) => m.verifyUrl);
    const existing = await Cert.find({
      id: { $in: user.certs },
      verifyUrl: { $in: verifyUrls },
    }).select("verifyUrl -_id");
    const existingSet = new Set(existing.map((e: { verifyUrl: string }) => e.verifyUrl));

    const toInsert = mapped.filter((m) => !existingSet.has(m.verifyUrl)).map((m) => m.data);

    if (toInsert.length === 0) {
      return res.status(200).json({ success: "OK", imported: 0, skipped: mapped.length });
    }

    await Cert.insertMany(toInsert);
    user.certs.push(...toInsert.map((c: { id: string }) => c.id));
    await user.save();

    return res.status(200).json({
      success: "OK",
      imported: toInsert.length,
      skipped: mapped.length - toInsert.length,
    });
  } catch (err) {
    console.error("LinkedIn import error:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

export default router;
