const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const expressValidator = require("express-validator");
const cors = require("cors");

dotenv.config();

// Initialize app and set port
const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(expressValidator());
app.use(cors()); // Enable CORS for all origins

// Check if JWT_SECRET is set
if (!process.env.JWT_SECRET) {
    console.error("JWT_SECRET is not set in the environment variables");
    process.exit(1);
}

// Database connection (MongoDB with Mongoose)
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.log(err));

// User model (MongoDB)
const User = require("./models/user");

// Password validation regex (minimum 8 characters, at least 1 letter, 1 number, and 1 special character)
const passwordValidationRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

// Route to handle user registration
app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    // Input validation and sanitization
    req.checkBody("username", "Username is required").notEmpty();
    req.checkBody("password", "Password is required").notEmpty();
    req.checkBody("password", "Password must be at least 8 characters long, include 1 letter, 1 number, and 1 special character").matches(passwordValidationRegex);

    const errors = req.validationErrors();
    if (errors) {
        return res.status(400).json({ errors });
    }

    // Sanitize inputs
    const sanitizedUsername = username.trim();
    const sanitizedPassword = password.trim();

    // Check if the user already exists
    const existingUser = await User.findOne({ username: sanitizedUsername });
    if (existingUser) {
        return res.status(400).json({ message: "Username already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(sanitizedPassword, 10);
    const newUser = new User({ username: sanitizedUsername, password: hashedPassword });

    try {
        await newUser.save();
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error registering user" });
    }
});

// Route to handle user login
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    // Input validation and sanitization
    req.checkBody("username", "Username is required").notEmpty();
    req.checkBody("password", "Password is required").notEmpty();

    const errors = req.validationErrors();
    if (errors) {
        return res.status(400).json({ errors });
    }

    // Sanitize inputs
    const sanitizedUsername = username.trim();
    const sanitizedPassword = password.trim();

    const user = await User.findOne({ username: sanitizedUsername });
    if (!user) return res.status(400).json({ message: "User not found" });

    const validPassword = await bcrypt.compare(sanitizedPassword, user.password);
    if (!validPassword) return res.status(400).json({ message: "Invalid credentials" });

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Login successful", token });
});

// Middleware to protect routes (e.g., dashboard)
function authenticateToken(req, res, next) {
    const token = req.header("Authorization") && req.header("Authorization").split(" ")[1];
    if (!token) return res.status(401).json({ message: "Access denied" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid token" });
        req.user = user;
        next();
    });
}

// Dashboard route (protected)
app.get("/dashboard", authenticateToken, (req, res) => {
    res.send(`<h1>Welcome to the Dashboard, ${req.user.userId}</h1>`);
});

// Logout route
app.get("/logout", (req, res) => {
    // Destroy the session or JWT
    res.json({ message: "You have logged out successfully" });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});