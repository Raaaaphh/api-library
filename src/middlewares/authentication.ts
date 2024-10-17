import * as express from "express";
import * as jwt from "jsonwebtoken";

export function expressAuthentication(
  request: express.Request,
  securityName: string,
  scopes?: string[]
): Promise<any> {
  if (securityName === "jwt") {
    const token = request.headers.authorization?.split(" ")[1];

    return new Promise((resolve, reject) => {
      if (!token) {
        return reject(new Error("No token provided"));
      }

      jwt.verify(token, process.env.JWT_SECRET ?? 'your_jwt_secret_key', (err: any, decoded: any) => {
        if (err) {
          return reject(new Error("Token is invalid or expired"));
        }

        if (scopes !== undefined) {
          const hasScopes = scopes.every(scope => decoded.scopes.includes(scope));
          if (!hasScopes) {
            return reject(new Error("Insufficient scope"));
          }
        }

        resolve(decoded);
      });
    });
  } else {
    return Promise.reject(new Error(`Security definition '${securityName}' not found`));
  }
}
