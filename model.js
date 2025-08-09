const mongoose = require('mongoose');
const { Schema } = mongoose;

const UserSchema = new Schema({
  email: String, password: String,
  role: { type: String, enum: ['learner', 'admin'], default: 'learner' },
  googleId: String
});
const LessonSchema = new Schema({
  title: String, skill: String, content: String
});
const QuizSchema = new Schema({
  lessonId: Schema.Types.ObjectId,
  questions: [{
    question: String,
    type: String,      // "mcq", "tf", "fill"
    options: [String],
    answer: String
  }]
});
const ProgressSchema = new Schema({
  userId: Schema.Types.ObjectId,
  lessonId: Schema.Types.ObjectId,
  completed: Boolean
});
const CertificateSchema = new Schema({
  userId: Schema.Types.ObjectId,
  lessonId: Schema.Types.ObjectId,
  date: Date,
  certId: String
});

module.exports = mongoose.model;
module.exports.User = mongoose.model('User', UserSchema);
module.exports.Lesson = mongoose.model('Lesson', LessonSchema);
module.exports.Quiz = mongoose.model('Quiz', QuizSchema);
module.exports.Progress = mongoose.model('Progress', ProgressSchema);
module.exports.Certificate = mongoose.model('Certificate', CertificateSchema);
