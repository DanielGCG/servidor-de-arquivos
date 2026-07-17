require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const http = require('http');

// Módulos refatorados
const config = require('./src/config');
const auth = require('./src/auth');
const services = require('./src/services');
const routes = require('./src/routes');

// 1. Inicializar configurações e pastas
config.initConfig();

// 2. Indexar arquivos existentes
services.indexExistingFiles();

// 3. Inicializar Express
const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());

// 4. Registrar rotas da API
app.use('/', routes);

// 5. Rota estática para acesso aos arquivos via Token
app.use('/files', auth.apiKeyMiddleware, (req, res, next) => {
  // O express.static não lida bem com caminhos que mudam em runtime
  // Então criamos um handler dinâmico
  const serveStatic = express.static(config.state.uploadFolder);
  return serveStatic(req, res, next);
});

// 6. Rota Painel Admin
app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// 7. Rodar servidor
const PORT = process.env.PORT || 3000;
http.createServer(app).listen(PORT, '0.0.0.0', function() {
  console.log(`[BOOT] Servidor de Arquivos rodando na porta ${PORT}`);
});