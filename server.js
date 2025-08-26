require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const http = require('http'); // Node 12 não precisa do 'https' para teste simples

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

// Middleware de autenticação via API key
function apiKeyMiddleware(req, res, next) {
  const key = req.headers['x-api-key'];
  if (key && key === process.env.API_KEY) next();
  else res.status(401).json({ error: 'Unauthorized' });
}

// Endpoint para upload
app.post('/upload', apiKeyMiddleware, upload.single('file'), function(req, res) {
  const fileUrl = req.protocol + '://' + req.get('host') + '/files/' + req.file.filename;
  res.json({ message: 'Upload bem-sucedido', url: fileUrl });
});

// Servir arquivos da pasta uploads
app.use('/files', express.static(uploadFolder));

// Teste de API
app.get('/', function(req, res) {
  res.send('Servidor de arquivos ativo com Node 12');
});

app.post('/webhook', express.json(), (req, res) => {
  // Verificar a senha simples
  const senha = req.headers['x-webhook-pass']; // cliente envia no header
  if (senha !== process.env.WEBHOOK_SECRET) {
    return res.status(401).send('Senha incorreta');
  }

  // Verificação do GitHub
  const secret = process.env.GITHUB_SECRET;
  const sig = req.headers['x-hub-signature-256'];

  const crypto = require('crypto');
  const hmac = crypto.createHmac('sha256', secret);
  const digest = 'sha256=' + hmac.update(JSON.stringify(req.body)).digest('hex');

  if (sig !== digest) {
    return res.status(401).send('Invalid signature');
  }

  // Rodar script de atualização
  const { exec } = require('child_process');
  exec('/home/ubuntu/servidor-de-arquivos/update.sh', (err, stdout, stderr) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Erro ao atualizar: ' + stderr);
    }
    console.log(stdout);
    res.send('Atualização aplicada');
  });
});

// Rodar servidor HTTP simples
const PORT = process.env.PORT || 3000;
http.createServer(app).listen(PORT, '0.0.0.0', function() {
  console.log('Servidor rodando na porta ' + PORT);
});