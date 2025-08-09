const express = require('express');
const router = express.Router();
const { Quiz, Progress, Certificate } = require('./models');
const { v4: uuidv4 } = require('uuid');
const PDFDocument = require('pdfkit');

// Middleware to authenticate JWT (same as in backend.js)
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).send('Missing auth token');
  const token = auth.split(' ')[1];
  try {
    const jwt = require('jsonwebtoken');
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).send('Invalid token');
  }
}

// Limits retakes to maxAttempts (e.g., 3)
const MAX_ATTEMPTS = 3;

router.use(authenticate);

// Get quiz for lesson
router.get('/:lessonId', async (req, res) => {
  const quiz = await Quiz.findOne({ lessonId: req.params.lessonId });
  if (!quiz) return res.status(404).send('Quiz not found');
  // Do not send answers!
  const questions = quiz.questions.map(q => ({
    question: q.question,
    type: q.type,
    options: q.options || []
  }));
  res.json({ lessonId: quiz.lessonId, questions });
});

// Submit quiz answers
router.post('/:lessonId/submit', async (req, res) => {
  const quiz = await Quiz.findOne({ lessonId: req.params.lessonId });
  if (!quiz) return res.status(404).send('Quiz not found');

  // Check attempts
  const attempts = await Progress.countDocuments({
    userId: req.user.id,
    lessonId: re
