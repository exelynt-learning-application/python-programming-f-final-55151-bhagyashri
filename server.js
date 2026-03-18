// server.js
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const { body, validationResult } = require("express-validator");
const cors = require("cors");
const helmet = require("helmet");

dotenv.config();

// Check if JWT_SECRET is set
if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET not configured in environment variables");
}

// Initialize app and set port
const app = express();
const port = 3000;

// Middleware
app.use(express.json());

// Use helmet for basic security headers
app.use(helmet());

// Configure CORS with specific origins
const allowedOrigins = ['http://localhost:3000', 'https://yourdomain.com'];
app.use(cors({
    origin: allowedOrigins,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Serve static files (HTML, CSS, JS)
app.use(express.static("public"));

// Rate limiter for login and registration routes
const rateLimit = require("express-rate-limit");
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: "Too many requests, please try again later."
});

// Apply rate limiter to specific routes
app.use("/login", limiter);
app.use("/register", limiter);

// Database connection (MongoDB with Mongoose)
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.log(err));

// User model (MongoDB)
const User = require("./models/user");

// Password validation: minimum 8 characters, at least 1 letter and 1 number
const passwordValidationRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&#^()_+\-=]{8,}$/;

// Route to handle user registration
app.post("/register", [
    body("username").notEmpty().withMessage("Username is required").trim().escape(),
    body("password").matches(passwordValidationRegex).withMessage("Password must be at least 8 characters long, include 1 letter and 1 number")
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password } = req.body;
        const sanitizedUsername = username.trim();

        const existingUser = await User.findOne({ username: sanitizedUsername });
        if (existingUser) {
            return res.status(400).json({ message: "Username already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username: sanitizedUsername, password: hashedPassword });

        await newUser.save();
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error registering user" });
    }
});

// Route to handle user login
app.post("/login", [
    body("username").notEmpty().withMessage("Username is required").trim().escape(),
    body("password").notEmpty().withMessage("Password is required")
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password } = req.body;
        const sanitizedUsername = username.trim();

        const user = await User.findOne({ username: sanitizedUsername });
        if (!user) return res.status(400).json({ message: "Invalid credentials" });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ message: "Invalid credentials" });

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ message: "Login successful", token });
    } catch (error) {
        res.status(500).json({ message: "Error logging in" });
    }
});

// Middleware to protect routes (e.g., dashboard)
function authenticateToken(req, res, next) {
    const authHeader = req.header("Authorization");
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Access denied" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid token" });
        req.user = user;
        next();
    });
}

// Dashboard route (protected)
app.get("/dashboard", authenticateToken, (req, res) => {
    res.json({ message: `Welcome to the Dashboard`, userId: req.user.userId });
});

// Logout route
app.get("/logout", (req, res) => {
    res.json({ message: "You have logged out successfully" });
});

// Centralized error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
