const isAuth = async (req, res, next) =>{
    try {
        let token = req.cookies.token;
        if(!token) {
            return res.status(401).json({message: "Unauthorized, user does not have token"})
        }
        const verifyToken = jwt.verify(token, Process.env.JWT_SECRET)
        if(!verifyToken){
            return res.status(401).json({message: "Unauthorized, user does not have valid token"})
        }
        req.userId = verifyToken.userId
        next()
    } catch (error) {
        return res.status(500).json(
            {message:`Error in isAuth ${error}`}
        )
    }
}
export default isAuth;