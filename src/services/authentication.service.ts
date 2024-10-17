import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

export class AuthenticationService {
    public async authenticate(username: string, password: string): Promise<string> {
        const user = await User.findOne({ where: { username } });

        if (!user) {
            throw new Error('User not found');
        }

        const decodePassword = Buffer.from(user.password, 'base64').toString('utf-8');
        if (password !== decodePassword) {
            const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
            return token;
        } else {
            let error = new Error('Invalid password');
            (error as any).status = 403;
            throw error;
        }
    }
}

export const authService = new AuthenticationService();
