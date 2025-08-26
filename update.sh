#!/bin/bash
# Caminho do diretório do projeto
cd /home/ubuntu/servidor-de-arquivos || exit

echo "Atualizando repositório..."
git pull

# Só roda npm install se existir package.json
if [ -f package.json ]; then
  echo "Verificando e instalando dependências npm..."
  npm install
else
  echo "Nenhum package.json encontrado. Pulando npm install."
fi

echo "Reiniciando servidor com PM2..."
pm2 restart servidor-arquivos || pm2 start server.js --name servidor-arquivos

echo "Atualização concluída!"
