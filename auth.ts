
import dotenv from "dotenv";
import { JWTPayload, jwtVerify, SignJWT } from "jose";

dotenv.config();

export const jwtsecret = Deno.env.get("JWT_SECRET");
if (!jwtsecret) {
  throw new Error("JWT_SECRET missing");
}
const secret = new TextEncoder().encode(jwtsecret);

export async function createJWT(payload: JWTPayload): Promise<string> {
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(secret);

  return jwt;
}

export async function verifyJWT(token: string): Promise<JWTPayload | null> {
  try {
    const { payload } = await jwtVerify(token, secret);
    return payload;
  } catch (_error: Error | any) {
    return null;
  }
}

export const checkAuth = async (
  username: string,
  token: string,
): Promise<boolean> => {
  if (!username || !token) {
    return false;
  }
  if (token) {
    const userlegit = await verifyJWT(token);
    if (userlegit != null) {
      return userlegit.username?.toString() === username;
    }
  }
  return false;
};

export const getuserJWT = async (token: string): Promise<string> => {
  if (!token) {
    return "error";
  }
  if (token) {
    const userlegit = await verifyJWT(token);
    if (userlegit?.username) {
      return userlegit.username.toString();
    }
  }
  return "error";
};
