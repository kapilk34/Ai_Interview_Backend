import express from 'express'
import dotenv from 'dotenv'
import connectDB from './config/connectDB.js';
import cookieParser from 'cookie-parser';
dotenv.config()
import cors from "cors"
import authRouter from './routes/authRoute.js';
import userRouter from './routes/userRoute.js';

const app = express()

app.use(cors({
    origin: process.env.CLIENT_PORT,
    credentials: true
}));
app.use(express.json())
app.use(cookieParser())

app.use("/api/auth", authRouter)
app.use("/api/user", userRouter)

const PORT = process.env.PORT || 8000;
app.listen(PORT, ()=>{
    console.log(`Server is running on port ${PORT}`)
    connectDB();
})

