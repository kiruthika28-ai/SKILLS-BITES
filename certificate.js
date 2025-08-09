const express = require('express');
const router = express.Router();
const PDFDocument = require('pdfkit');
const { Certificate, User, Lesson } = require('./models');

// Route: Download certificate PDF by certId
router.get('/:certId/download', async (req, res) => {
  const cert = await Certificate.findOne({ certId: req.params.certId });
  if (!cert) return res.status(404).send('Certificate not found');

  const user = await User.findById(cert.userId);
  const lesson = await Lesson.findById(cert.lessonId);

  // Create PDF
  const doc = new PDFDocument();

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${cert.certId}.pdf"`);

  doc.fontSize(25).text('Micro-Certificate of Completion', { align: 'center' });
  doc.moveD
