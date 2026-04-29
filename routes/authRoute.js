import express from "express"
import { googleAuth, register, login, logOut } from "../controllers/authController.js"

const authRouter = express.Router()

// OAuth Authentication
authRouter.post("/google", googleAuth);

// Email/Password Authentication
authRouter.post("/register", register);
authRouter.post("/login", login);

// Logout
authRouter.get("/logout", logOut);

export default authRouter;