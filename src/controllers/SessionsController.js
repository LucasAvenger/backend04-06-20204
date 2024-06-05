const knex = require("../database/knex");
const { compare } = require("bcryptjs");
const AppError = require("../utils/AppError");
const authConfig = require("../controllers/configs/auth");
const { sign } = require("jsonwebtoken");

class SessionsController {
    async create(request, response) {
        const { email, password } = request.body;

        const user = await knex("users").where({ email }).first();

        if (!user) {
            throw new AppError("E-mail e/ou senha incorreta", 401);
        }

        const passwordMached = await compare(password, user.password);

        if (!passwordMached) {
            throw new AppError("E-mail e/ou senha incorreta", 401);
        }
        const { secret, expiresIn } = authConfig.jwt;
        const token = sign({}, secret, {
            subject: String(user.id),
            expiresIn
        })

        return response.json({ user, token });
    }
}

module.exports = SessionsController;