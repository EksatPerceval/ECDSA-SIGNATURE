const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { ec: EC } = require('elliptic');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const ec = new EC('p256'); // NIST P-256 (secp256r1)

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Multer config - memory storage
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// In-memory store for keys and signatures
const keyStore = {};
const signatureStore = {};

// ─── UTILITIES ───────────────────────────────────────────────────────────────

function hashBuffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function uint8ArrayToHex(arr) {
  return Buffer.from(arr).toString('hex');
}

function hexToUint8Array(hex) {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

// ─── API ROUTES ───────────────────────────────────────────────────────────────

// Generate ECDSA Key Pair
app.post('/api/generate-keys', (req, res) => {
  try {
    const { owner } = req.body;
    const keyId = uuidv4();
    const keyPair = ec.genKeyPair();

    const privateKeyHex = keyPair.getPrivate('hex');
    const publicKeyHex = keyPair.getPublic('hex');
    const publicKeyCompressed = keyPair.getPublic(true, 'hex');

    // Store keys server-side (in production: store only public key)
    keyStore[keyId] = {
      keyId,
      owner: owner || 'Anonymous',
      privateKeyHex,
      publicKeyHex,
      publicKeyCompressed,
      createdAt: new Date().toISOString(),
    };

    res.json({
      success: true,
      keyId,
      owner: owner || 'Anonymous',
      publicKey: publicKeyHex,
      publicKeyCompressed,
      privateKey: privateKeyHex,
      curve: 'P-256 (secp256r1)',
      createdAt: keyStore[keyId].createdAt,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Sign PDF
app.post('/api/sign', upload.single('pdf'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No PDF uploaded.' });

    const { privateKey, signerName, keyId } = req.body;
    if (!privateKey) return res.status(400).json({ success: false, error: 'Private key required.' });

    const pdfBuffer = req.file.buffer;
    const fileHash = hashBuffer(pdfBuffer);

    // ECDSA Sign
    const keyPair = ec.keyFromPrivate(privateKey, 'hex');
    const signature = keyPair.sign(fileHash);
    const derSignature = signature.toDER('hex');
    const publicKeyHex = keyPair.getPublic('hex');

    const sigId = uuidv4();
    const timestamp = new Date().toISOString();

    // Embed signature into PDF as metadata annotation
    const pdfDoc = await PDFDocument.load(pdfBuffer);
    const helveticaFont = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const helveticaBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

    // Add signature stamp to last page
    const pages = pdfDoc.getPages();
    const lastPage = pages[pages.length - 1];
    const { width, height } = lastPage.getSize();

    const stampW = 320;
    const stampH = 90;
    const stampX = width - stampW - 24;
    const stampY = 24;

    // Stamp background
    lastPage.drawRectangle({
      x: stampX,
      y: stampY,
      width: stampW,
      height: stampH,
      color: rgb(0.97, 0.98, 1.0),
      borderColor: rgb(0.2, 0.4, 0.9),
      borderWidth: 1.2,
      opacity: 1,
    });

    // Title bar
    lastPage.drawRectangle({
      x: stampX,
      y: stampY + stampH - 22,
      width: stampW,
      height: 22,
      color: rgb(0.18, 0.35, 0.85),
    });

    lastPage.drawText('ECDSA DIGITAL SIGNATURE', {
      x: stampX + 8,
      y: stampY + stampH - 15,
      size: 9,
      font: helveticaBold,
      color: rgb(1, 1, 1),
    });

    const lines = [
      `Signer : ${signerName || 'Unknown'}`,
      `Sig ID : ${sigId.substring(0, 18)}...`,
      `Hash   : ${fileHash.substring(0, 28)}...`,
      `Date   : ${timestamp.replace('T', ' ').substring(0, 19)} UTC`,
      `Curve  : NIST P-256 (secp256r1)`,
    ];

    lines.forEach((line, i) => {
      lastPage.drawText(line, {
        x: stampX + 10,
        y: stampY + stampH - 38 - i * 11,
        size: 7.5,
        font: helveticaFont,
        color: rgb(0.15, 0.15, 0.25),
      });
    });

    // Set PDF metadata
    pdfDoc.setTitle(pdfDoc.getTitle() || 'Signed Document');
    pdfDoc.setAuthor(signerName || 'ECDSA Signer');
    pdfDoc.setSubject(`ECDSA Signed - SigID: ${sigId}`);
    pdfDoc.setKeywords([`sigId:${sigId}`, `hash:${fileHash}`, `sig:${derSignature.substring(0, 40)}`]);

    const signedPdfBytes = await pdfDoc.save();
    const signedPdfBuffer = Buffer.from(signedPdfBytes);
    const signedHash = hashBuffer(signedPdfBuffer);

    // Store signature record
    signatureStore[sigId] = {
      sigId,
      originalHash: fileHash,
      signedHash,
      derSignature,
      publicKeyHex,
      signerName: signerName || 'Unknown',
      timestamp,
      fileName: req.file.originalname,
    };

    res.json({
      success: true,
      sigId,
      originalHash: fileHash,
      signedHash,
      signature: derSignature,
      publicKey: publicKeyHex,
      signerName: signerName || 'Unknown',
      timestamp,
      signedPdf: signedPdfBuffer.toString('base64'),
      algorithm: 'ECDSA with SHA-256 on P-256',
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Verify PDF
app.post('/api/verify', upload.single('pdf'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No PDF uploaded.' });

    const { signature, publicKey, sigId } = req.body;

    // If sigId provided, retrieve from store
    let derSignature = signature;
    let pubKeyHex = publicKey;
    let storedRecord = null;

    if (sigId && signatureStore[sigId]) {
      storedRecord = signatureStore[sigId];
      derSignature = storedRecord.derSignature;
      pubKeyHex = storedRecord.publicKeyHex;
    }

    if (!derSignature || !pubKeyHex) {
      return res.status(400).json({ success: false, error: 'Signature and public key required.' });
    }

    const pdfBuffer = req.file.buffer;
    const fileHash = hashBuffer(pdfBuffer);

    let isValid = false;
    let verifiedHash = '';

    try {
      const keyPair = ec.keyFromPublic(pubKeyHex, 'hex');
      // Try verifying against the current file hash
      isValid = keyPair.verify(fileHash, derSignature);
      verifiedHash = fileHash;

      // If not valid and we have stored record, try the original hash
      if (!isValid && storedRecord) {
        isValid = keyPair.verify(storedRecord.originalHash, derSignature);
        if (isValid) verifiedHash = storedRecord.originalHash;
      }
    } catch (e) {
      isValid = false;
    }

    const result = {
      success: true,
      isValid,
      fileHash,
      verifiedHash,
      algorithm: 'ECDSA with SHA-256 on P-256',
      timestamp: new Date().toISOString(),
    };

    if (storedRecord) {
      result.signerName = storedRecord.signerName;
      result.signedAt = storedRecord.timestamp;
      result.fileName = storedRecord.fileName;
    }

    if (!isValid) {
      result.reason = 'Signature does not match the document hash. Document may have been tampered.';
    }

    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// List stored signatures
app.get('/api/signatures', (req, res) => {
  const list = Object.values(signatureStore).map(s => ({
    sigId: s.sigId,
    signerName: s.signerName,
    fileName: s.fileName,
    timestamp: s.timestamp,
    originalHash: s.originalHash,
  }));
  res.json({ success: true, signatures: list });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', curve: 'P-256', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\n🔐 ECDSA PDF Signer Backend running on http://localhost:${PORT}\n`);
});
