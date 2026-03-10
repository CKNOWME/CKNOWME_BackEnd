import { CredlyBadge, CredlySkill } from "./types.ts";
import { getuserJWT } from "./auth.ts";
import { Request } from "express";

export const parseDate = (value?: string | null): number | null => {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
};

export const PRIVATE_IPS = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
  /^::1$/,
  /^localhost$/i,
];
export const PRIVATE_IP_RANGES = [/^172\.(1[6-9]|2\d|3[0-1])\./];

export const isPrivateHost = (hostname: string): boolean => {
  return PRIVATE_IPS.some((rule) => rule.test(hostname)) ||
    PRIVATE_IP_RANGES.some((rule) => rule.test(hostname));
};

export const validatePublicUrl = (rawUrl: string): boolean => {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return false;
    }
    if (isPrivateHost(parsed.hostname)) return false;
    return true;
  } catch {
    return false;
  }
};

export const ensureSafeUrls = (urls: string[]): boolean => {
  for (const url of urls) {
    if (!url) continue;
    if (!validatePublicUrl(url)) return false;
  }
  return true;
};

export const resolveAuthUser = async (req: Request): Promise<string | null> => {
  const jwt = req.cookies?.bearer;
  if (!jwt) return null;
  const username = await getuserJWT(jwt);
  if (username === "error") return null;
  return username;
};

export const extractCredlySlug = (rawUrl: string): string | null => {
  try {
    const parsed = new URL(rawUrl);
    const host = parsed.hostname.toLowerCase();
    if (host !== "www.credly.com" && host !== "credly.com") return null;
    if (!validatePublicUrl(rawUrl)) return null;

    const path = parsed.pathname.replace(/\/+$/, "");
    if (path.startsWith("/users/")) {
      const slug = path.split("/")[2];
      return slug || null;
    }
  } catch (_err: Error | unknown) {
    return null;
  }
  return null
};

export const badgeEndpointFor = (slug: string): string => {
  return `https://www.credly.com/users/${slug}`;
};

export const getCredlyBadges = async (id:string):Promise<CredlyBadge[] | null>=>{
  const url = `https://www.credly.com/users/${id}/badges`;
  const res = await fetch(url, {
    headers: {
      "Accept": "application/json",
      "X-Requested-With": "XMLHttpRequest",
      "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
      "Accept-Language": "es-ES,es;q=0.9",
      "Sec-Ch-Ua": '"Chromium";v="145", "Not:A-Brand";v="99"',
      "Sec-Ch-Ua-Mobile": "?0",
      "Sec-Ch-Ua-Platform": '"macOS"',
      "Sec-Fetch-Site": "same-origin",
      "Sec-Fetch-Mode": "cors",
      "Sec-Fetch-Dest": "empty",
      "Accept-Encoding": "gzip, deflate, br",
      "Priority": "u=1, i",
    },
  });
  if(!res.ok){
    const body = await res.text();
    return null;
  }
  const text = await res.text();
  if (text.trim().startsWith("<")) {
    return null;
  }
  const data = JSON.parse(text);
  return data.data;
}

export const normalizeTags = (skills?: CredlySkill[]): string[] => {
  if (!skills) return [];
  return skills
    .map((s) => (s?.name || "").trim())
    .filter(Boolean)
    .slice(0, 12);
};

export const issuerFrom = (badge: CredlyBadge): string => {
  const templateIssuer = badge.badge_template?.issuer?.entities?.[0]?.entity
    ?.name;
  if (templateIssuer) return templateIssuer;
  const issuerEntity = badge.issuer?.entities?.[0]?.entity?.name;
  if (issuerEntity) return issuerEntity;
  const summary = badge.issuer?.summary || "";
  if (summary.toLowerCase().startsWith("issued by ")) {
    return summary.slice("issued by ".length).trim() || "Credly";
  }
  return summary || "Credly";
};




export type LinkedInCert = {
  title: string;
  issuer: string;
  issuedAt?: number;
  expiresAt?: number;
  credentialId?: string;
  verifyUrl?: string;
  photo?: string;
};

const MONTHS_ES: Record<string, number> = {
  ene: 0,
  feb: 1,
  mar: 2,
  abr: 3,
  may: 4,
  jun: 5,
  jul: 6,
  ago: 7,
  sept: 8,
  sep: 8,
  oct: 9,
  nov: 10,
  dic: 11,
};

const parseEsMonthYear = (value: string): number | undefined => {
  const match = value.toLowerCase().match(/(ene|feb|mar|abr|may|jun|jul|ago|sept|sep|oct|nov|dic)\.?\s+(\d{4})/i);
  if (!match) return undefined;
  const month = MONTHS_ES[match[1].replace('.', '')];
  const year = parseInt(match[2], 10);
  if (month === undefined) return undefined;
  return Date.UTC(year, month, 1);
};

export const parseLinkedinCerts = (payload: any): LinkedInCert[] => {
  const included = Array.isArray(payload?.included) ? payload.included : [];
  const list = included.find((item: any) =>
    typeof item?.entityUrn === "string" && item.entityUrn.includes("LICENSES_AND_CERTIFICATIONS_VIEW_DETAILS")
  );
  const elements = Array.isArray(list?.components?.elements)
    ? list.components.elements
    : Array.isArray(list?.components?.elements?.elements)
    ? list.components.elements.elements
    : [];

  const findVectorImage = (node: any): { rootUrl: string; artifacts: any[] } | null => {
    if (!node) return null;
    if (node.vectorImage?.rootUrl && Array.isArray(node.vectorImage?.artifacts)) {
      return { rootUrl: node.vectorImage.rootUrl, artifacts: node.vectorImage.artifacts };
    }
    if (node.rootUrl && Array.isArray(node.artifacts)) {
      return { rootUrl: node.rootUrl, artifacts: node.artifacts };
    }
    if (Array.isArray(node)) {
      for (const item of node) {
        const found = findVectorImage(item);
        if (found) return found;
      }
    } else if (typeof node === "object") {
      for (const value of Object.values(node)) {
        const found = findVectorImage(value);
        if (found) return found;
      }
    }
    return null;
  };

  const getImageUrl = (node: any): string | undefined => {
    const vec = findVectorImage(node);
    if (!vec) return undefined;
    const best = vec.artifacts.reduce((acc: any, cur: any) => {
      if (!acc) return cur;
      return (cur.width || 0) > (acc.width || 0) ? cur : acc;
    }, null);
    if (!best?.fileIdentifyingUrlPathSegment || !vec.rootUrl) return undefined;
    return `${vec.rootUrl}${best.fileIdentifyingUrlPathSegment}`;
  };

  const parseCaption = (caption?: string): { issuedAt?: number; expiresAt?: number } => {
    if (!caption) return {};
    const issued = caption.match(/Expedici[oó]n\s+([^·]+)/i);
    const expires = caption.match(/Vencimiento:?\s*([^·]+)/i);
    const issuedAt = issued ? parseEsMonthYear(issued[1].trim()) : undefined;
    const expiresAt = expires ? parseEsMonthYear(expires[1].trim()) : undefined;
    return { issuedAt, expiresAt };
  };

  const certs: LinkedInCert[] = [];
  for (const element of elements) {
    const entity = element?.components?.entityComponent;
    if (!entity) continue;

    const title = entity?.titleV2?.text?.text || entity?.title?.text?.text || "";
    const issuer = entity?.subtitle?.text?.text || entity?.subtitleV2?.text?.text || "";
    if (!title || !issuer) continue;

    const caption = entity?.caption?.text?.text;
    const { issuedAt, expiresAt } = parseCaption(caption);

    const credentialId = entity?.metadata?.text?.text
      ?.replace(/ID de la credencial\s*/i, "").trim();
    const verifyUrl = entity?.textActionTarget || entity?.actionTarget;

    const photo = getImageUrl(element) || getImageUrl(entity);

    certs.push({
      title,
      issuer,
      issuedAt,
      expiresAt,
      credentialId,
      verifyUrl,
      photo,
    });
  }

  return certs;
};


const decodeHtmlEntities = (input: string): string => {
  return input
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&#(\d+);/g, (_m, code) => String.fromCharCode(parseInt(code, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_m, code) => String.fromCharCode(parseInt(code, 16)));
};

const stripHtml = (input: string): string => {
  return decodeHtmlEntities(input.replace(/<[^>]*>/g, '')).replace(/\s+/g, ' ').trim();
};

export const parseLinkedinHtmlList = (html: string): LinkedInCert[] => {
  const blocks = Array.from(html.matchAll(/<li class="pvs-list__paged-list-item[\s\S]*?<\/li>/g));
  const certs: LinkedInCert[] = [];

  for (const match of blocks) {
    const block = match[0];
    const titleMatch = block.match(/<span[^>]*aria-hidden="true"[^>]*>(.*?)<\/span>/);
    const title = titleMatch ? stripHtml(titleMatch[1]) : '';

    const issuerMatch = block.match(/<span[^>]*class="[^"]*t-14[^"]*"[^>]*>\s*<span[^>]*aria-hidden="true"[^>]*>(.*?)<\/span>/);
    const issuer = issuerMatch ? stripHtml(issuerMatch[1]) : '';

    const dateMatch = block.match(/Expedici[^<]*/i);
    const dateLine = dateMatch ? stripHtml(dateMatch[0]) : '';
    const issued = dateLine.match(/Expedici[oó]n\s+([^·]+)/i);
    const exp = dateLine.match(/Vencimiento:?\s*([^·]+)/i);
    const issuedAt = issued ? parseEsMonthYear(issued[1].trim()) : undefined;
    const expiresAt = exp ? parseEsMonthYear(exp[1].trim()) : undefined;

    const idMatch = block.match(/ID de la credencial[^<]*/i);
    const credentialId = idMatch ? stripHtml(idMatch[0]).replace(/^ID de la credencial\s*/i, '') : undefined;

    const hrefs = Array.from(block.matchAll(/href="(https?:\/\/[^"]+)"/g)).map((m) => decodeHtmlEntities(m[1]));
    const verifyUrl = hrefs.find((h) => !h.includes('linkedin.com/company') && !h.includes('linkedin.com/in/'));

    const imgMatch = block.match(/<img[^>]*src="(https?:\/\/[^"]+)"[^>]*>/);
    const photo = imgMatch ? decodeHtmlEntities(imgMatch[1]) : undefined;

    if (title && issuer) {
      certs.push({ title, issuer, issuedAt, expiresAt, credentialId, verifyUrl, photo });
    }
  }

  return certs;
};

export const parseLinkedBadges = (payload: any): LinkedInCert[] => {
  return parseLinkedinCerts(payload);
};

