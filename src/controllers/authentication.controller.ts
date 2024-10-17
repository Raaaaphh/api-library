import { Body, Controller, Post, Route } from "tsoa";
import { AuthInputDTO } from "../dto/authentication.dto";
import { authService } from "../services/authentication.service";

@Route("auth")
export class AuthenticationController extends Controller {

    @Post("/")
    public async authenticate(
        @Body() requestBody: AuthInputDTO
    ) {
        const { grant_type, username, password } = requestBody;
        if (grant_type !== 'password') {
            let error = new Error('Invalid grant_type');
            (error as any).status = 400;
            throw error;
        }
        const token = await authService.authenticate(username, password);
        return { token };
    }
}

