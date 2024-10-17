import * as express from "express";
import * as jwt from "jsonwebtoken";

export function expressAuthentication(
  request: express.Request,
  securityName: string,
  scopes?: string[]
): Promise<any> {
  if (securityName === "jwt") {
    const token = request.headers.authorization;

    return new Promise((resolve, reject) => {
      if (!token) {
        return reject(new Error("No token provided"));
      }

      jwt.verify(token, process.env.JWT_SECRET ?? 'your_jwt_secret_key', (err: any, decoded: any) => {
        if (err) {
          return reject(new Error("Token is invalid or expired"));
        } else {
          if (scopes !== undefined) {
            if (scopes.filter((s) => decoded.scopes.includes(s)).length === 0) {
              reject(new Error("JWT does not contain required scope."));
            }
          }
        }
        resolve(decoded);
      });
    });
  } else {
    return Promise.reject(new Error(`Security definition '${securityName}' not found`));
  }
}
