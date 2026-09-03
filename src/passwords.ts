import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import type { PasswordHasher } from "./ports.js";

const scrypt = promisify(scryptCallback);

export class ScryptPasswordHasher implements PasswordHasher {
  async hash(password: string) {
    const salt = randomBytes(16);
    const derived = await scrypt(password, salt, 64) as Buffer;
    return `scrypt$${salt.toString("base64url")}$${derived.toString("base64url")}`;
  }

  async verify(password: string, storedHash: string) {
    const [algorithm, encodedSalt, encodedHash] = storedHash.split("$");
    if (algorithm !== "scrypt" || !encodedSalt || !encodedHash) return false;
    const expected = Buffer.from(encodedHash, "base64url");
    const actual = await scrypt(password, Buffer.from(encodedSalt, "base64url"), expected.length) as Buffer;
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }
}
