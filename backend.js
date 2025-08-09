require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const PDFDocument = require('pdfkit');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

// DB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// Schemas & Models
const UserSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  role: { type: String, enum: ['learner', 'admin'], default: 'learner' }
});
const LessonSchema = new mongoose.Schema({
  title: String,
  skill: String,
  content: String
});
const QuizSchema = new mongoose.Schema({
  lessonId: mongoose.Schema.Types.ObjectId,
  questions: [{
    question: String,
    type: String, // 'mcq', 'tf', 'fill'
    options: [String],
    answer: String
  }]
});
const ProgressSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  lessonId: mongoose.Schema.Types.ObjectId,
  completed: Boolean
});
const CertificateSchema = new mongoose.Schema({
  certId: String,
  userId: mongoose.Schema.Types.ObjectId,
  lessonId: mongoose.Schema.Types.ObjectId,
  date: Date
});

const User = mongoose.model('User', UserSchema);
const Lesson = mongoose.model('Lesson', LessonSchema);
const Quiz = mongoose.model('Quiz', QuizSchema);
const Progress = mongoose.model('Progress', ProgressSchema);
const Certificate = mongoose.model('Certificate', CertificateSchema);

// JWT Middleware
const authenticate = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).send('Missing auth token');
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).send('Invalid token');
  }
};

// Role-based Middleware
const authorize = role => (req, res, next) => {
  if (req.user.role !== role) return res.status(403).send('Forbidden');
  next();
};

// Passport Google OAuth Setup
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      user = await User.create({
        email: profile.emails[0].value,
        googleId: profile.id,
        role: 'learner'
      });
    }
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

app.use(session({ secret: 'sessionsecret', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// Routes

// Register (email + password)
app.post('/register', async (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password) return res.status(400).send('Email and password required');
  const existing = await User.findOne({ email });
  if (existing) return res.status(400).send('Email exists');
  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({ email, password: hashed, role: role || 'learner' });
  res.json({ message: 'Registered', userId: user._id });
});

// Login (email + password)
app.post('/login', async (req, res) =
