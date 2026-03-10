import express, { Request, Response } from "express";
import { User } from "../DB/user.ts";
import { Cert } from "../DB/cert.ts";
import { userIpRateLimiter } from "../security.ts";
import {CredlyResponse} from "../types.ts"
import {resolveAuthUser,extractCredlySlug,badgeEndpointFor,issuerFrom,parseDate,normalizeTags,ensureSafeUrls} from "../util.ts"

const router = express.Router();
router.use(userIpRateLimiter);

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

    const rawUrl = typeof req.body?.url === "string" ? req.body.url.trim() : "";
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
        "Sec-Ch-Ua-Platform": '"macOS"',
        "Accept-Language": "es-ES,es;q=0.9",
        "Accept": "application/json",
        "Sec-Ch-Ua": '"Chromium";v="145", "Not:A-Brand";v="99"',
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": `https://www.credly.com/users/${slug}/badges`,
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i",
      },
    });
    console.log(await response.json())
    if (!response.ok) {
      return res.status(502).json({ error: "Credly fetch failed" });
    }

    const json = (await response.json()) as CredlyResponse;
    const badges = Array.isArray(json.data) ? json.data : [];

    if (badges.length === 0) {
      return res.status(200).json({ success: "OK", imported: 0, skipped: 0 });
    }

    const mapped = badges
      .map((badge): { data: any; verifyUrl: string } | null => {
        const date = parseDate(badge.issued_at_date);
        if (!date) return null;

        const title = badge.badge_template?.name || "Credly Badge";
        const issuer = issuerFrom(badge);
        const description = badge.badge_template?.description || "";
        const photo = badge.badge_template?.image_url || badge.image_url || "";
        const verifyUrl = `https://www.credly.com/earner/earned/badge/${badge.id}`;
        const pdfUrl = `https://www.credly.com/earner/earned/share/${badge.id}`;
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
  } catch (_err) {
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

export default router;
