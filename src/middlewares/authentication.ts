import * as express from "express";
import * as jwt from "jsonwebtoken";

export function expressAuthentication(
  request: express.Request,
  securityName: string,
  scopes?: string[]
): Promise<any> {
  if (securityName === /*clef du securityDefinition */) {
    const token = //Récupérer le token

    return new Promise((resolve, reject) => {
      if (!token) {
        reject(/*throw error no token*/);
      }
      jwt.verify(
        token,
        /*your secret*/,
        function (err: any, decoded: any) {
          if (err) {
            reject(err);
          } else {
            if (scopes !== undefined) {
              //Custom verif
            }
            resolve(decoded);
          }
        }
      );
    });
  } else {
    /* throw error not found securityDefinition*/
  }
}
