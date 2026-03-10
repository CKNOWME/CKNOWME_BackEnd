/*
----------------------------------------------------------
Security measures to prevent DoS, XSS, SSRF, RCE, NoSQL injection
----------------------------------------------------------
*/

import { NextFunction, Request, Response } from "express";
import helmet from "helmet";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";

const PRIVATE_IPS = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
  /^::1$/,
  /^localhost$/i,
];

const PRIVATE_IP_RANGES = [
  /^172\.(1[6-9]|2\d|3[0-1])\./,
];

const SSRF_FIELD_NAMES = ["url", "uri", "link", "callback", "webhook", "redirect"];
const RCE_FIELD_NAMES = ["cmd", "command", "exec", "script", "shell"];
const SHELL_META = /[;&|`$<>\\]/;
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/g;

const containsScriptTag = (input: string): boolean => /<\s*script\b/i.test(input);

// String clean
const sanitizeString = (input: string): string => {
  return input
    .replace(CONTROL_CHARS, "")
    .replace(/<\s*\/\s*script\s*>/gi, "")
    .replace(/<\s*script\b[^>]*>/gi, "")
    .trim();
};

const sanitizeValue = (value: unknown): unknown => {
  if (typeof value === "string") return sanitizeString(value);

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item));
  }

  if (value && typeof value === "object") {
    const source = value as Record<string, unknown>;
    const cleaned: Record<string, unknown> = {};

    for (const [key, val] of Object.entries(source)) {
      // NoSQL inj
      if (key.includes("$") || key.includes(".")) continue;
      cleaned[key] = sanitizeValue(val);
    }

    return cleaned;
  }

  return value;
};

const findStringValues = (value: unknown, bucket: string[] = []): string[] => {
  if (typeof value === "string") {
    bucket.push(value);
    return bucket;
  }

  if (Array.isArray(value)) {
    for (const item of value) findStringValues(item, bucket);
    return bucket;
  }

  if (value && typeof value === "object") {
    for (const item of Object.values(value as Record<string, unknown>)) {
      findStringValues(item, bucket);
    }
  }

  return bucket;
};

// SSRF
const isPrivateHost = (hostname: string): boolean => {
  return PRIVATE_IPS.some((rule) => rule.test(hostname)) ||
    PRIVATE_IP_RANGES.some((rule) => rule.test(hostname));
};

// SSRF
const validateOutboundUrl = (rawUrl: string): boolean => {
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

export const securityHeaders = helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: "same-site" },
});

// Basic IP rate-limit
export const apiRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests" },
});

export const authRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests" },
  keyGenerator: (req: Request) => {
    const username = typeof req.body?.username === "string" ? req.body.username : "";
    return `${ipKeyGenerator(req)}:${username}`;
  },
});

export const userIpRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests" },
  keyGenerator: (req: Request) => {
    const token = typeof req.cookies?.bearer === "string" ? req.cookies.bearer : "";
    return `${ipKeyGenerator(req)}:${token}`;
  },
});

export const csrfGuard = (
  req: Request,
  res: Response,
  next: NextFunction,
): void | Response => {
  const method = req.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
    return next();
  }
  const cookieToken = req.cookies?.csrf;
  const headerToken = req.headers["x-csrf-token"] as string | undefined;
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: "CSRF token invalid" });
  }
  return next();
};

// Global Protection
export const requestSecurityGuards = (
  req: Request,
  res: Response,
  next: NextFunction,
): void | Response => {
  const rawBody = req.body;
  const rawQuery = req.query;
  const rawParams = req.params;

  const rawStrings = [
    ...findStringValues(rawBody),
    ...findStringValues(rawQuery),
    ...findStringValues(rawParams),
  ];

  if (rawStrings.some((value) => containsScriptTag(value))) {
    return res.status(400).json({ error: "XSS detected" });
  }

  const sanitizedBody = sanitizeValue(rawBody);
  const sanitizedQuery = sanitizeValue(rawQuery);
  const sanitizedParams = sanitizeValue(rawParams);

  req.body = sanitizedBody;

  for (const [key, value] of Object.entries((sanitizedBody as Record<string, unknown>) ?? {})) {
    if (RCE_FIELD_NAMES.includes(key.toLowerCase()) && typeof value === "string") {
      if (SHELL_META.test(value)) {
        return res.status(400).json({ error: "RCE detected" });
      }
    }
  }

  for (const [key, value] of Object.entries((sanitizedBody as Record<string, unknown>) ?? {})) {
    if (!SSRF_FIELD_NAMES.includes(key.toLowerCase())) continue;
    if (typeof value !== "string" || !validateOutboundUrl(value)) {
      return res.status(400).json({ error: "SSRF detected" });
    }
  }

  const allStrings = [
    ...findStringValues(sanitizedBody),
    ...findStringValues(sanitizedQuery),
    ...findStringValues(sanitizedParams),
  ];

  if (allStrings.some((value) => containsScriptTag(value))) {
    return res.status(400).json({ error: "XSS detected" });
  }

  next();
};

export const safeCityName = (value: unknown): string | null => {
  if (typeof value !== "string") return null;
  const cleaned = sanitizeString(value);
  if (!/^[\p{L}0-9 .,'-]{2,60}$/u.test(cleaned)) return null;
  return cleaned;
};

export const safeId = (value: unknown): string | null => {
  if (typeof value !== "string") return null;
  const cleaned = sanitizeString(value);
  if (!/^[a-zA-Z0-9_-]{2,64}$/.test(cleaned)) return null;
  return cleaned;
};
