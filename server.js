const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require("fs"); // Import fs module
const { exec } = require("child_process"); // Import child_process module
const axios = require("axios");
require('dotenv').config();

const app = express();

const RAPIDAPI_KEY = process.env.RAPIDAPI_KEY;
const ONECOMPILER_URL = "https://onecompiler-apis.p.rapidapi.com/api/v1/run";
const MONGO_URI = process.env.MONGO_URI;
const MONGO_COMPILER_URI = process.env.MONGO_COMPILER_URI;



const languageMap = {
  javascript: "javascript",
  python: "python",
  c: "c",
  cpp: "cpp",
  java: "java",
  sql: "sql",
  mongodb: "mongodb"
};
  
// Middleware
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({ storage });

// MongoDB Connection
const uri = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

async function main() {
    const client = new MongoClient(uri);

    try {
        await client.connect();
        console.log("Connected to MongoDB");

        const db = client.db("LEARNWEAVE");
        const usersCollection = db.collection("users");
        const challengesCollection = db.collection("challenges");
        const notificationsCollection = db.collection("notifications");
        const solutionsCollection = db.collection("solutions");
        let savedOTPs = {};

        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: {
                user: process.env.SMTP_EMAIL,
                pass: process.env.SMTP_PASSWORD,
            },
        });

        function generateOtp() {
            return Math.floor(1000 + Math.random() * 9000).toString();
        }

        function generateToken(email) {
            return jwt.sign({ email }, JWT_SECRET, { expiresIn: '2d' });
        }
        

        async function validateChallenge(question, topic, language) {
            try {
                const response = await fetch('https://copilot5.p.rapidapi.com/copilot', {
                    method: 'POST',
                    headers: {
                        'x-rapidapi-key': process.env.OPENAI_API_KEY,
                        'x-rapidapi-host': 'copilot5.p.rapidapi.com',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        message: `Is the following challenge related to coding? Analyze the topic (${topic}), language (${language}), and question (${question}). Respond with exactly "Yes" or "No".`,
                        conversation_id: null,
                        markdown: true
                    })
                });
        
                if (!response.ok) {
                    throw new Error(`API request failed with status ${response.status}`);
                }
        
                const result = await response.json();
                console.log('API Response:', result); // For debugging
                
                // Extract the answer from the correct path in the response
                const answer = result.data?.message?.toLowerCase().trim();
                
                if (!answer) {
                    console.error('No valid answer found in API response');
                    return false;
                }
                
                return answer === 'yes';
            } catch (error) {
                console.error('Error validating challenge:', error);
                return false; // Default to false if validation fails
            }
        }


        app.post('/sendotp', async (req, res) => {
            const { email } = req.body;
            if (!email) return res.status(400).json({ message: "Email is required" });

            const otp = generateOtp();
            const mailOptions = {
                from: process.env.SMTP_EMAIL,
                to: email,
                subject: "OTP Verification",
                html: `<p>Your OTP from Learnweave is <strong>${otp}</strong>. It will expire in 2 minutes.</p>`,
            };

            transporter.sendMail(mailOptions, (error) => {
                if (error) return res.status(500).json({ message: "Failed to send OTP" });

                savedOTPs[email] = otp;
                setTimeout(() => delete savedOTPs[email], 120000);
                res.status(200).json({ message: "OTP sent successfully" });
            });
        });

        app.post('/verify', (req, res) => {
            const { email, otp } = req.body;
            if (!email || !otp) return res.status(400).json({ message: "Email and OTP are required" });

            if (savedOTPs[email] && savedOTPs[email] === otp) {
                delete savedOTPs[email];
                return res.status(200).json({ message: "OTP verified successfully" });
            }
            res.status(400).json({ message: "Invalid or expired OTP" });
        });

        app.post('/signup', async (req, res) => {
          const { fullName, email, password } = req.body;
      
          if (!fullName || !email || !password) {
              return res.status(400).json({ message: "All fields are required" });
          }
      
          try {
              const userExists = await usersCollection.findOne({ email });
              if (userExists) {
                  return res.status(400).json({ message: "User already exists" });
              }
      
              const hashedPassword = await bcrypt.hash(password, 10);
              const newUser = {
                  fullName,
                  email,
                  password: hashedPassword,
                  lastLogin: new Date(),
                  supercoins: 0,
                  token: null // Initialize token as null
              };
      
              const result = await usersCollection.insertOne(newUser);
      
              // Generate token with user details
              const token = jwt.sign(
                  {
                      userId: result.insertedId.toString(),
                      email: newUser.email,
                      fullName: newUser.fullName,
                  },
                  JWT_SECRET,
                  { expiresIn: "2d" }
              );
      
              // Store token in user collection
              await usersCollection.updateOne(
                  { _id: result.insertedId },
                  { $set: { token: token } }
              );
      
              console.log("Token generated and stored:", token); // Log token
              res.status(201).json({ message: "User signed up successfully", token });
          } catch (err) {
              res.status(500).json({ message: "An error occurred, please try again" });
          }
      });
      
      app.post('/login', async (req, res) => {
          const { email, password } = req.body;
      
          try {
              const user = await usersCollection.findOne({ email });
              if (!user || !(await bcrypt.compare(password, user.password))) {
                  return res.status(401).json({ message: "Invalid credentials" });
              }
      
              // Generate token with user details
              const token = jwt.sign(
                  {
                      userId: user._id.toString(),
                      email: user.email,
                      fullName: user.fullName,
                  },
                  JWT_SECRET,
                  { expiresIn: "2d" }
              );
      
              // Update token in user collection
              await usersCollection.updateOne(
                  { _id: user._id },
                  { $set: { token: token } }
              );
      
              console.log("Token updated and stored:", token); // Log token
              res.status(200).json({ message: "Login successful", token });
          } catch (err) {
              console.error(err);
              res.status(500).json({ message: "Internal server error" });
          }
      });

        app.post('/check-user', async (req, res) => {
            const { email } = req.body;
            if (!email) return res.status(400).json({ message: "Email is required" });

            try {
                const user = await usersCollection.findOne({ email });
                if (!user) {
                    return res.status(404).json({ message: "User not found" });
                }

                const currentDate = new Date();
                const lastLoginDate = new Date(user.lastLogin);
                const timeDifference = currentDate - lastLoginDate;
                const daysDifference = timeDifference / (1000 * 60 * 60 * 24);

                if (daysDifference > 2) {
                    return res.status(401).json({ message: "Token expired. Please log in again." });
                }

                await usersCollection.updateOne({ email }, { $set: { lastLogin: new Date() } });

                const token = generateToken(email);
                res.status(200).json({ message: "User found", token, user: { fullName: user.fullName, email: user.email, photo: user.photo } });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Internal server error" });
            }
        });

        app.post('/reset-password', async (req, res) => {
            const { email, newPassword } = req.body;
            if (!email || !newPassword) return res.status(400).json({ message: "Email and new password are required" });

            try {
                const user = await usersCollection.findOne({ email });
                if (!user) return res.status(404).json({ message: "User not found" });

                const hashedPassword = await bcrypt.hash(newPassword, 10);
                await usersCollection.updateOne({ email }, { $set: { password: hashedPassword } });

                res.status(200).json({ message: "Password reset successfully" });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Internal server error" });
            }
        });

        app.get('/get-profile', async (req, res) => {
            const token = req.headers.authorization?.split(' ')[1];
            if (!token) return res.status(401).json({ message: "Unauthorized" });
        
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                const user = await usersCollection.findOne({ email: decoded.email });
                if (!user) return res.status(404).json({ message: "User not found" });
        
                // Calculate total supercoins
                const challengeCoins = await challengesCollection.aggregate([
                    { $match: { userId: user._id } },
                    { $group: { _id: null, totalSupercoins: { $sum: "$supercoins" } } }
                ]).toArray();
                const solutionCoins = await solutionsCollection.aggregate([
                    { $match: { userId: user._id } },
                    { $group: { _id: null, totalSupercoins: { $sum: "$supercoins" } } }
                ]).toArray();
        
                const totalSupercoins = (challengeCoins[0]?.totalSupercoins || 0) + (solutionCoins[0]?.totalSupercoins || 0);
        
                res.status(200).json({ 
                    user: { 
                        fullName: user.fullName, 
                        email: user.email, 
                        photo: user.photo,
                        supercoins: totalSupercoins,
                    } 
                });
            } catch (err) {
                console.error(err);
                res.status(401).json({ message: "Invalid token" });
            }
        });

        app.post('/update-profile', upload.single('photo'), async (req, res) => {
            const token = req.headers.authorization?.split(' ')[1];
            if (!token) return res.status(401).json({ message: "Unauthorized" });

            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                const { fullName } = req.body;
                const photo = req.file ? `/uploads/${req.file.filename}` : null;

                const updateData = { fullName };
                if (photo) updateData.photo = photo;

                await usersCollection.updateOne(
                    { email: decoded.email },
                    { $set: updateData }
                );

                const updatedUser = await usersCollection.findOne({ email: decoded.email });
                res.status(200).json({ 
                    message: "Profile updated successfully", 
                    user: { 
                        fullName: updatedUser.fullName, 
                        email: updatedUser.email, 
                        photo: updatedUser.photo,
                        supercoins: updatedUser.supercoins,
                    } 
                });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Internal server error" });
            }
        });

        app.post('/submit-challenge', async (req, res) => {
            const token = req.headers.authorization?.split(' ')[1];
            if (!token) return res.status(401).json({ message: "Unauthorized" });
        
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                const { language, difficulty: rawDifficulty, topic, question, testCases, steps, answer } = req.body;
        
                // Standardize difficulty format
                const difficulty = rawDifficulty.charAt(0).toUpperCase() + rawDifficulty.slice(1).toLowerCase();
        
                if (!language || !difficulty || !topic || !question || !testCases || !steps) {
                    return res.status(400).json({ message: "All fields except answer are required" });
                }
        
                // Validate the challenge
                const isValidChallenge = await validateChallenge(question, topic, language);
                if (!isValidChallenge) {
                    return res.status(400).json({ message: "This is not a valid coding challenge. Please submit a coding-related question." });
                }
        
                // Find the user
                const user = await usersCollection.findOne({ email: decoded.email });
                if (!user) return res.status(404).json({ message: "User not found" });
        
                // Calculate supercoins based on difficulty
                let supercoins = 0;
                if (difficulty === 'Basic') supercoins = 3;
                else if (difficulty === 'Intermediate') supercoins = 5;
                else if (difficulty === 'Advanced') supercoins = 7;
        
                // Create the challenge
                const challenge = {
                    userId: user._id,
                    language,
                    difficulty,
                    topic,
                    question,
                    testCases,
                    steps,
                    answer: answer || null,
                    supercoins, // Supercoins assigned to the challenge
                    createdAt: new Date(),
                };
        
                // Insert the challenge into the challenges collection
                const result = await challengesCollection.insertOne(challenge);
        
                // Add supercoins to the user's profile when the challenge is created
                await usersCollection.updateOne(
                    { _id: user._id },
                    { $inc: { supercoins: supercoins } } // Increment the user's supercoins
                );
        
                // Create a notification
                const notificationMessage = `${user.fullName} has submitted a new challenge in ${language} (${difficulty} level).`;
                await notificationsCollection.insertOne({
                    message: notificationMessage,
                    seenBy: [], // Initially, no one has seen this notification
                    createdBy: user.email, // Add the email of the user who created the notification
                    createdAt: new Date(),
                });
        
                res.status(201).json({ message: "Challenge submitted successfully", challengeId: result.insertedId });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Internal server error" });
            }
        });


       // Notifications Backend code
       /*app.get('/notifications', async (req, res) => {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ message: "Unauthorized" });
    
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const user = await usersCollection.findOne({ email: decoded.email });
            if (!user) return res.status(404).json({ message: "User not found" });
    
            // Fetch notifications that are not created by the current user
            const notifications = await notificationsCollection.find({ createdBy: { $ne: decoded.email } }).toArray();
            console.log("Fetched notifications:", notifications); // Debugging
            res.status(200).json({ notifications });
        } catch (err) {
            console.error(err);
            res.status(500).json({ message: "Internal server error" });
        }
    });*/

    // Updated notifications endpoint
// Add this to your server file (likely server.js or routes file)
app.get('/notifications', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await usersCollection.findOne({ email: decoded.email });
        if (!user) return res.status(404).json({ message: "User not found" });

        // Fetch notifications that are not created by the current user
        const notifications = await notificationsCollection.find({ createdBy: { $ne: decoded.email } }).toArray();
        console.log("Fetched notifications:", notifications); // Debugging
        res.status(200).json({ notifications });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal server error" });
    }
});

app.post('/notifications/mark-seen', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        await notificationsCollection.updateMany(
            { seenBy: { $ne: decoded.email } },
            { $addToSet: { seenBy: decoded.email } }
        );
        res.status(200).json({ message: "Notifications marked as seen" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal server error" });
    }
});



        app.get('/challenges', async (req, res) => {
            const token = req.headers.authorization?.split(' ')[1];
            if (!token) return res.status(401).json({ message: "Unauthorized" });
        
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                const { language } = req.query;
                const uppercaseLanguage = language.toUpperCase(); // Convert to uppercase
        
                // Get the user ID from the decoded token
                const userId = decoded.userId;
        
                // Fetch challenges that are not posted by the current user
                const challenges = await challengesCollection.find({ 
                    language: uppercaseLanguage,
                    userId: { $ne: new ObjectId(userId) } // Exclude challenges posted by the current user
                }).toArray();
        
                res.status(200).json({ challenges });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Internal server error" });
            }
        });
          

          app.get('/challenges/:id', async (req, res) => {
            const token = req.headers.authorization?.split(' ')[1];
            if (!token) return res.status(401).json({ message: "Unauthorized" });
          
            try {
              const challengeId = req.params.id;
              const challenge = await challengesCollection.findOne({ _id: new ObjectId(challengeId) });
              if (!challenge) {
                return res.status(404).json({ message: "Challenge not found" });
              }
              res.status(200).json({ challenge });
            } catch (err) {
              console.error(err);
              res.status(500).json({ message: "Internal server error" });
            }
          });


 // Save submission to the database
 async function saveToDatabase(submission) {
  try {
    await solutionsCollection.insertOne(submission);
  } catch (error) {
    console.error("MongoDB Error:", error);
  }
}

app.get("/solutions", async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    try {
        const { challengeId } = req.query;
        if (!challengeId) {
            return res.status(400).json({ message: "Challenge ID is required" });
        }

        const solutions = await solutionsCollection.find({
            challengeId: new ObjectId(challengeId),
        }).toArray();

        res.status(200).json({ solutions });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Add these routes to your server.js

// Get user's challenges
// Get user's challenges with language aggregation
app.get('/api/user-challenges', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await usersCollection.findOne({ email: decoded.email });
        if (!user) return res.status(404).json({ message: "User not found" });

        // Aggregate challenges by language
        const challenges = await challengesCollection.aggregate([
            { $match: { userId: user._id } },
            { 
                $group: {
                    _id: "$language",
                    count: { $sum: 1 }
                }
            }
        ]).toArray();

        // Convert to { language: count } format
        const challengeCounts = challenges.reduce((acc, curr) => {
            acc[curr._id] = curr.count;
            return acc;
        }, {});

        res.status(200).json(challengeCounts);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Get user's solutions with language aggregation
app.get('/api/user-solutions', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await usersCollection.findOne({ email: decoded.email });
        if (!user) return res.status(404).json({ message: "User not found" });

        // Aggregate solutions by challenge language
        const solutions = await solutionsCollection.aggregate([
            {
                $lookup: {
                    from: "challenges",
                    localField: "challengeId",
                    foreignField: "_id",
                    as: "challenge"
                }
            },
            { $unwind: "$challenge" },
            {
                $group: {
                    _id: "$challenge.language",
                    count: { $sum: 1 }
                }
            }
        ]).toArray();

        // Convert to { language: count } format
        const solutionCounts = solutions.reduce((acc, curr) => {
            acc[curr._id] = curr.count;
            return acc;
        }, {});

        res.status(200).json(solutionCounts);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal server error" });
    }
});

app.get('/total-supercoins/:userId', async (req, res) => {
    const userId = req.params.userId;

    // Validate userId
    if (!ObjectId.isValid(userId)) {
        return res.status(400).json({ message: "Invalid user ID" });
    }

    try {
        // Sum supercoins from challenges
        const challenges = await challengesCollection.find({ userId: new ObjectId(userId) }).toArray();
        const challengeCoins = challenges.reduce((total, challenge) => total + (challenge.supercoins || 0), 0);

        // Sum supercoins from solutions
        const solutions = await solutionsCollection.find({ userId: new ObjectId(userId) }).toArray();
        const solutionCoins = solutions.reduce((total, solution) => total + (solution.supercoins || 0), 0);

        // Total supercoins
        const totalSupercoins = challengeCoins + solutionCoins;

        res.status(200).json({ totalSupercoins });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal server error" });
    }
});



   // Add this to your server.js routes
app.post('/get-help', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    try {
        const { challengeId } = req.body;
        if (!challengeId) {
            return res.status(400).json({ message: "Challenge ID is required" });
        }

        // Get the challenge details
        const challenge = await challengesCollection.findOne({ 
            _id: new ObjectId(challengeId) 
        });
        
        if (!challenge) {
            return res.status(404).json({ message: "Challenge not found" });
        }

        // Prepare the prompt
        const prompt = `Provide a step-by-step guide to solve the following programming challenge:\n\n
        Topic: ${challenge.topic}\n
        Language: ${challenge.language}\n
        Question: ${challenge.question}\n\n
        Provide detailed steps, explanations, and code snippets if necessary.`;

        // Call the Copilot5 API
        const response = await fetch('https://copilot5.p.rapidapi.com/copilot', {
            method: 'POST',
            headers: {
                'x-rapidapi-key': process.env.OPENAI_API_KEY,
                'x-rapidapi-host': 'copilot5.p.rapidapi.com',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: prompt,
                conversation_id: null,
                markdown: true
            })
        });

        if (!response.ok) {
            throw new Error(`API request failed with status ${response.status}`);
        }

        const result = await response.json();
        
        // Extract the guide from the response
        const guide = result.data?.message || "No guide could be generated.";
        res.status(200).json({ guide });

    } catch (error) {
        console.error('Error getting help:', error);
        res.status(500).json({ 
            message: "Error generating guide", 
            details: error.message 
        });
    }
});


    // Compile Code Endpoint
    // Updated compile endpoint with better error handling
    app.post("/compile", async (req, res) => {
        console.log("Compile request received:", req.body); // Log the request body
    
        const { language, code, challengeId, userId } = req.body;
    
        // Validate input
        if (!language || !code || !challengeId || !userId) {
            return res.status(400).json({ error: "Missing required fields" });
        }
    
        // Convert language to lowercase
        const normalizedLanguage = language.toLowerCase();
    
        // Check if the language is supported
        if (!languageMap[normalizedLanguage]) {
            return res.status(400).json({ error: "Unsupported language" });
        }
    
        try {
            // Check if the user has already solved this challenge
            const existingSolution = await solutionsCollection.findOne({
                challengeId: new ObjectId(challengeId),
                userId: new ObjectId(userId),
            });
    
            if (existingSolution) {
                return res.status(400).json({
                    message: "You already solved this challenge. Please try to solve other challenges.",
                });
            }
    
            // Fetch the challenge from the database
            const challenge = await challengesCollection.findOne({
                _id: new ObjectId(challengeId),
            });
    
            if (!challenge) {
                return res.status(404).json({ error: "Challenge not found" });
            }
    
            const testCases = challenge.testCases;
            const results = [];
            let allPassed = true;
    
            // Execute code for each test case
            for (let i = 0; i < testCases.length; i++) {
                const stdin = testCases[i].input;
    
                try {
                    const response = await axios.post(
                        ONECOMPILER_URL,
                        {
                            language: languageMap[language.toLowerCase()],
                            stdin: stdin,
                            files: [{ name: "main.c", content: code }],
                        },
                        {
                            headers: {
                                "x-rapidapi-key": RAPIDAPI_KEY,
                                "x-rapidapi-host": "onecompiler-apis.p.rapidapi.com",
                                "Content-Type": "application/json",
                            },
                            timeout: 10000,
                        }
                    );
    
                    const result = response.data;
    
                    // Combine stdout, stderr, and error into a single output
                    const output = [result.stdout, result.stderr, result.error]
                    .filter(Boolean)
                    .join("\n") || "No output";
    
                    // Check if the output matches the expected output
                    const passed = output.trim() === testCases[i].output.trim();
                    results.push({
                        input: testCases[i].input,
                        expectedOutput: testCases[i].output,
                        actualOutput: output.trim(),
                        passed,
                    });
    
                    if (!passed) {
                        allPassed = false;
                    }
                } catch (innerError) {
                    console.error("Error running code:", innerError);
                    results.push({
                        input: testCases[i].input,
                        expectedOutput: testCases[i].output,
                        actualOutput: `Error: ${innerError.message}`,
                        passed: false,
                    });
                    allPassed = false;
                }
            }
    
            // Save the solution if all test cases passed
            if (allPassed) {
                // Calculate supercoins based on challenge difficulty
                let coinsToAdd = 0;
                switch (challenge.difficulty.toLowerCase()) {
                    case 'basic':
                        coinsToAdd = 3;
                        break;
                    case 'intermediate':
                        coinsToAdd = 5;
                        break;
                    case 'advanced':
                        coinsToAdd = 7;
                        break;
                    default:
                        coinsToAdd = 0;
                }
    
                const solution = {
                    challengeId: new ObjectId(challengeId),
                    userId: new ObjectId(userId),
                    code,
                    results,
                    createdAt: new Date(),
                    supercoins: coinsToAdd, // Add supercoins to the solution
                };
    
                await solutionsCollection.insertOne(solution);
    
                // Add coins to the user's profile based on the difficulty level
                await usersCollection.updateOne(
                    { _id: new ObjectId(userId) },
                    { $inc: { supercoins: coinsToAdd } }
                );
            }
    
            // Return the results
            res.json({ results, allPassed });
        } catch (error) {
            console.error("Compilation Error:", error);
            res.status(500).json({
                error: "Execution failed",
                details: error.message,
            });
        }
    });
  const PORT = process.env.PORT;
   app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    });

    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}

main().catch(console.error);