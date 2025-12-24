require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const http = require('http');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());

// Criar pasta de uploads se não existir
const uploadFolder = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadFolder)) fs.mkdirSync(uploadFolder);


// Configuração do Multer para suportar subpastas
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    let folder = req.query.folder || '';
    // Sanitizar nome da pasta
    folder = folder.replace(/[^a-zA-Z0-9-_]/g, '');
    const dest = path.join(uploadFolder, folder);
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    cb(null, dest);
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


// Middleware de autenticação por API key
function apiKeyMiddleware(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (apiKey && apiKey === process.env.API_KEY) {
    console.log(`[API] Autenticado: ${apiKey}`);
    next();
  } else {
    console.log(`[API] Falha na autenticação. Recebido: ${apiKey}`);
    res.status(401).json({ error: 'Não autorizado' });
  }
}


// Endpoint para upload (protegido, suporta subpastas)
app.post('/upload', apiKeyMiddleware, upload.single('file'), function(req, res) {
  const folder = req.query.folder ? req.query.folder.replace(/[^a-zA-Z0-9-_]/g, '') : '';
  const fileUrl = req.protocol + '://' + req.get('host') + '/files/' + (folder ? folder + '/' : '') + req.file.filename;
  console.log(`[UPLOAD] Arquivo recebido: ${req.file.originalname} -> ${req.file.filename} (pasta: ${folder})`);
  res.json({ message: 'Upload bem-sucedido', url: fileUrl, filename: req.file.filename, folder });
});


// Endpoint para remoção de arquivos (protegido, suporta subpastas) - recebe caminho via body JSON
app.delete('/delete', apiKeyMiddleware, function(req, res) {
  const relPath = req.body.filepath || '';
  if (!relPath) {
    console.log('[DELETE] Falha: filepath não informado no corpo da requisição');
    return res.status(400).json({ error: 'filepath obrigatório no corpo da requisição' });
  }
  // Sanitizar cada parte do caminho
  const safePath = relPath.split('/').map(p => p.replace(/[^a-zA-Z0-9-_.]/g, '')).join(path.sep);
  const filePath = path.join(uploadFolder, safePath);
  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (err) {
      console.log(`[DELETE] Arquivo não encontrado: ${filePath}`);
      return res.status(404).json({ error: 'Arquivo não encontrado' });
    }
    fs.unlink(filePath, (err) => {
      if (err) {
        console.log(`[DELETE] Erro ao remover: ${filePath}`);
        return res.status(500).json({ error: 'Erro ao remover arquivo' });
      }
      console.log(`[DELETE] Removido: ${filePath}`);
      res.json({ message: 'Arquivo removido com sucesso' });
    });
  });
});


// Servir arquivos da pasta uploads e subpastas
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