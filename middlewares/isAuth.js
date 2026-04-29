import jwt from "jsonwebtoken"
import dotenv from "dotenv"

dotenv.config()

const isAuth = async (req, res, next) =>{
    try {
        let token = req.cookies.token;
        if(!token) {
            return res.status(401).json({message: "Unauthorized, user does not have token"})
        }
        
        try {
            const verifyToken = jwt.verify(token, process.env.JWT_SECRET)
            if(!verifyToken){
                return res.status(401).json({message: "Unauthorized, user does not have valid token"})
            }
            req.userId = verifyToken.userId
            next()
        } catch (tokenError) {
            if (tokenError.name === 'TokenExpiredError') {
                return res.status(401).json({message: "Session expired. Please login again"})
            } else if (tokenError.name === 'JsonWebTokenError') {
                return res.status(401).json({message: "Invalid token. Please login again"})
            }
            throw tokenError
        }
    } catch (error) {
        return res.status(401).json(
            {message: "Authentication failed. Please login again"}
        )
    }
}
export default isAuth;