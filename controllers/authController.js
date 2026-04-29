import getToken from "../config/token.js"
import User from "../models/userModel.js"
import bcryptjs from "bcryptjs"

// Email validation utility function
const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
}

// Google Authentication
export const googleAuth = async (req,res) =>{
    try {
        const {name, email} = req.body
        
        // Validate email
        if (!isValidEmail(email)) {
            return res.status(400).json({ message: "Invalid email format" })
        }
        
        let user = await User.findOne({email})
        if(!user){
            user = await User.create({name, email})
        }

        let token = await getToken(user._id)
        res.cookie("token", token, {
            httpOnly: true,
            secure: false,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        })
        return res.status(200).json(user)
    } catch (error) {
        return res.status(500).json(
            {message:`Google auth error ${error}`}
        )
    }
}

// User Registration with Email and Password
export const register = async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body

        // Validation
        if (!name || !email || !password || !confirmPassword) {
            return res.status(400).json({ message: "All fields are required" })
        }

        // Validate email format
        if (!isValidEmail(email)) {
            return res.status(400).json({ message: "Invalid email format" })
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ message: "Passwords do not match" })
        }

        if (password.length < 6) {
            return res.status(400).json({ message: "Password must be at least 6 characters" })
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email })
        if (existingUser) {
            return res.status(409).json({ message: "User already registered with this email" })
        }

        // Hash password
        const hashedPassword = await bcryptjs.hash(password, 10)

        // Create new user
        const user = await User.create({
            name,
            email,
            password: hashedPassword
        })

        // Generate token
        const token = await getToken(user._id)
        res.cookie("token", token, {
            httpOnly: true,
            secure: false,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        // Return user data without password
        const userData = user.toObject()
        delete userData.password
        return res.status(201).json({ message: "User registered successfully", user: userData })

    } catch (error) {
        return res.status(500).json({ message: `Registration error: ${error.message}` })
    }
}

// User Login with Email and Password
export const login = async (req, res) => {
    try {
        const { email, password } = req.body

        // Validation
        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required" })
        }

        // Validate email format
        if (!isValidEmail(email)) {
            return res.status(400).json({ message: "Invalid email format" })
        }

        // Find user by email
        const user = await User.findOne({ email })
        if (!user) {
            return res.status(401).json({ message: "Invalid email or password" })
        }

        // Check if user has password (not OAuth user)
        if (!user.password) {
            return res.status(401).json({ message: "This account uses OAuth login. Please use Google Sign-In" })
        }

        // Compare passwords
        const isPasswordValid = await bcryptjs.compare(password, user.password)
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid email or password" })
        }

        // Generate token
        const token = await getToken(user._id)
        res.cookie("token", token, {
            httpOnly: true,
            secure: false,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        // Return user data without password
        const userData = user.toObject()
        delete userData.password
        return res.status(200).json({ message: "Login successful", user: userData })

    } catch (error) {
        return res.status(500).json({ message: `Login error: ${error.message}` })
    }
}

// Logout
export const logOut = async (req,res) =>{
    try {
        res.clearCookie("token")
        return res.status(200).json(
            {message:"LogOut Successfully!"}
        )
    } catch (error) {
        return res.status(500).json(
            {message:`Logout error ${error}`}
        )
    }
}