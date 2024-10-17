import { User } from "../models/user.model"; // Modèle Sequelize
import jwt from "jsonwebtoken"; // Pour générer le JWT
import { Buffer } from "buffer"; // Pour décoder Base64
import { notFound } from "../error/NotFoundError";

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";

export class AuthenticationService {
    public async authenticate(
        username: string,
        password: string
    ): Promise<string> {
        const user = await User.findOne({ where: { username } });

        if (!user) {
            throw notFound("User");
        }

        const decodedPassword = Buffer.from(user.password, "base64").toString(
            "utf-8"
        );

        if (password === decodedPassword) {
            let scopes;

            switch (username) {
                case "admin":
                    scopes = ["user:read", "user:write", "user:delete"];
                    break;
                case "gerant":
                    scopes = ["user:read", "user:write", "user:delete:bookCollection",];
                    break;
                default:
                    scopes = ["user:read", "user:write:book"];
            }

            const token = jwt.sign(
                { username: user.username, scopes: scopes },
                JWT_SECRET,
                {
                    expiresIn: "1h",
                }
            );

            return token;

        } else {
            let error = new Error("Wrong password");
            (error as any).status = 403;
            throw error;
        }
    }
}

export const authService = new AuthenticationService();
