const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// Serve static files from frontend
app.use(express.static(path.join(__dirname, "../frontEnd")));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, "uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});


// ENCRYPTION/DECRYPTION ALGORITHMS(i only have 4 at this time we willl add more here)


//AES-256 Encryption

function encryptAES(text, secretKey) {
  try {
    // Create a 32-byte key from the secret
    const key = crypto.scryptSync(secretKey, "salt", 32);
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");

    // Return IV + encrypted data
    return iv.toString("hex") + ":" + encrypted;
  } catch (error) {
    throw new Error("AES Encryption failed: " + error.message);
  }
}


//AES-256 Decryption

function decryptAES(encryptedData, secretKey) {
  try {
    const parts = encryptedData.split(":");
    if (parts.length !== 2) {
      throw new Error("Invalid encrypted data format");
    }

    const iv = Buffer.from(parts[0], "hex");
    const encrypted = parts[1];

    const key = crypto.scryptSync(secretKey, "salt", 32);
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);

    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  } catch (error) {
    throw new Error("AES Decryption failed: " + error.message);
  }
}


//Caesar Cipher Encryption

function encryptCaesar(text, shift = 3) {
  return text
    .split("")
    .map((char) => {
      if (char.match(/[a-z]/i)) {
        const code = char.charCodeAt(0);
        const isUpperCase = char === char.toUpperCase();
        const base = isUpperCase ? 65 : 97;
        return String.fromCharCode(((code - base + shift) % 26) + base);
      }
      return char;
    })
    .join("");
}


//Caesar Cipher Decryption

function decryptCaesar(text, shift = 3) {
  return encryptCaesar(text, 26 - shift);
}

/**
 * Base64 Encoding
 */
function encryptBase64(text) {
  return Buffer.from(text, "utf8").toString("base64");
}

//Base64 Decoding

function decryptBase64(encodedText) {
  return Buffer.from(encodedText, "base64").toString("utf8");
}

//ROT13 Encryption/Decryption (same function for both)

function rot13(text) {
  return text.replace(/[a-zA-Z]/g, (char) => {
    const start = char <= "Z" ? 65 : 97;
    return String.fromCharCode(
      start + ((char.charCodeAt(0) - start + 13) % 26),
    );
  });
}

// API ROUTES

// Health check endpoint

app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    message: "Encryption/Decryption API is running",
    timestamp: new Date().toISOString(),
  });
});

//Get available encryption methods

app.get("/api/methods", (req, res) => {
  res.json({
    methods: [
      {
        id: "aes",
        name: "AES-256",
        description: "Advanced Encryption Standard (256-bit)",
        requiresKey: true,
      },
      {
        id: "caesar",
        name: "Caesar Cipher",
        description: "Classic substitution cipher",
        requiresKey: false,
      },
      {
        id: "base64",
        name: "Base64",
        description: "Base64 encoding/decoding",
        requiresKey: false,
      },
      {
        id: "rot13",
        name: "ROT13",
        description: "Letter substitution cipher",
        requiresKey: false,
      },
    ],
  });
});


//Encrypt text

app.post("/api/encrypt", (req, res) => {
  try {
    const { text, method = "aes", key, shift } = req.body;

    if (!text) {
      return res.status(400).json({
        error: "Text is required",
      });
    }

    let encrypted;
    let usedKey = key;

    switch (method.toLowerCase()) {
      case "aes":
        if (!key) {
          return res.status(400).json({
            error: "Secret key is required for AES encryption",
          });
        }
        encrypted = encryptAES(text, key);
        break;

      case "caesar":
        const caesarShift = shift || 3;
        encrypted = encryptCaesar(text, caesarShift);
        usedKey = caesarShift.toString();
        break;

      case "base64":
        encrypted = encryptBase64(text);
        usedKey = "N/A";
        break;

      case "rot13":
        encrypted = rot13(text);
        usedKey = "N/A";
        break;

      default:
        return res.status(400).json({
          error: "Invalid encryption method",
        });
    }

    res.json({
      success: true,
      method: method,
      encrypted: encrypted,
      key: usedKey,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(500).json({
      error: error.message,
    });
  }
});

//Decrypt text

app.post("/api/decrypt", (req, res) => {
  try {
    const { text, method = "aes", key, shift } = req.body;

    if (!text) {
      return res.status(400).json({
        error: "Text is required",
      });
    }

    let decrypted;

    switch (method.toLowerCase()) {
      case "aes":
        if (!key) {
          return res.status(400).json({
            error: "Secret key is required for AES decryption",
          });
        }
        decrypted = decryptAES(text, key);
        break;

      case "caesar":
        const caesarShift = shift || 3;
        decrypted = decryptCaesar(text, caesarShift);
        break;

      case "base64":
        decrypted = decryptBase64(text);
        break;

      case "rot13":
        decrypted = rot13(text);
        break;

      default:
        return res.status(400).json({
          error: "Invalid decryption method",
        });
    }

    res.json({
      success: true,
      method: method,
      decrypted: decrypted,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(500).json({
      error: error.message,
    });
  }
});

//Encrypt file(works as of now but there are some issues with it)

app.post("/api/encrypt/file", upload.single("file"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: "No file uploaded",
      });
    }

    const { method = "aes", key, shift } = req.body;
    const fileContent = fs.readFileSync(req.file.path, "utf8");

    let encrypted;

    switch (method.toLowerCase()) {
      case "aes":
        if (!key) {
          fs.unlinkSync(req.file.path);
          return res.status(400).json({
            error: "Secret key is required for AES encryption",
          });
        }
        encrypted = encryptAES(fileContent, key);
        break;

      case "caesar":
        encrypted = encryptCaesar(fileContent, parseInt(shift) || 3);
        break;

      case "base64":
        encrypted = encryptBase64(fileContent);
        break;

      case "rot13":
        encrypted = rot13(fileContent);
        break;

      default:
        fs.unlinkSync(req.file.path);
        return res.status(400).json({
          error: "Invalid encryption method",
        });
    }

    // Clean up uploaded file
    fs.unlinkSync(req.file.path);

    res.json({
      success: true,
      method: method,
      encrypted: encrypted,
      originalFileName: req.file.originalname,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({
      error: error.message,
    });
  }
});

//Decrypt file(same as encrypt file, it works as of now but there are some issues with it)

app.post("/api/decrypt/file", upload.single("file"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: "No file uploaded",
      });
    }

    const { method = "aes", key, shift } = req.body;
    const fileContent = fs.readFileSync(req.file.path, "utf8");

    let decrypted;

    switch (method.toLowerCase()) {
      case "aes":
        if (!key) {
          fs.unlinkSync(req.file.path);
          return res.status(400).json({
            error: "Secret key is required for AES decryption",
          });
        }
        decrypted = decryptAES(fileContent, key);
        break;

      case "caesar":
        decrypted = decryptCaesar(fileContent, parseInt(shift) || 3);
        break;

      case "base64":
        decrypted = decryptBase64(fileContent);
        break;

      case "rot13":
        decrypted = rot13(fileContent);
        break;

      default:
        fs.unlinkSync(req.file.path);
        return res.status(400).json({
          error: "Invalid decryption method",
        });
    }

    // Clean up uploaded file
    fs.unlinkSync(req.file.path);

    res.json({
      success: true,
      method: method,
      decrypted: decrypted,
      originalFileName: req.file.originalname,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({
      error: error.message,
    });
  }
});


// ERROR HANDLING

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    path: req.path,
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Error:", err);
  res.status(500).json({
    error: "Internal server error",
    message: err.message,
  });
});


// START SERVER

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════╗
║   🔐 Encryption/Decryption API Server                 
║                                                       
║   Server running on: http://localhost:${PORT}        
║   API Endpoints:                                      
║   - GET  /api/health          (Health check)         
║   - GET  /api/methods         (Available methods)    
║   - POST /api/encrypt         (Encrypt text)         
║   - POST /api/decrypt         (Decrypt text)         
║   - POST /api/encrypt/file    (Encrypt file)         
║   - POST /api/decrypt/file    (Decrypt file)         
║                                                       
║   Frontend: http://localhost:${PORT}                 
╚═══════════════════════════════════════════════════════╝
    `);
});
