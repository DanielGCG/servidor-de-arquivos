require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const http = require('http'); // Node 12 não precisa do 'https' para teste simples
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// Criar pasta de uploads se não existir
const uploadFolder = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadFolder)) fs.mkdirSync(uploadFolder);

// Configuração do Multer
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, uploadFolder);
  },
  filename: function(req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: function(req, file, cb) {
    const allowed = ['image/jpeg', 'image/png', 'image/gif'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Tipo de arquivo não permitido'));
  }
});

// Endpoint para upload
app.post('/upload', apiKeyMiddleware, upload.single('file'), function(req, res) {
  const fileUrl = req.protocol + '://' + req.get('host') + '/files/' + req.file.filename;
  res.json({ message: 'Upload bem-sucedido', url: fileUrl });
});

// Servir arquivos da pasta uploads
app.use('/files', express.static(uploadFolder));

// Teste de API
app.get('/', function(req, res) {
  res.send('Servidor funcionando!!!');
});

// Rodar servidor HTTP simples
const PORT = process.env.PORT || 3000;
http.createServer(app).listen(PORT, '0.0.0.0', function() {
  console.log('Servidor rodando na porta ' + PORT);
});