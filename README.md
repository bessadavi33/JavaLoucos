# Sistema de Autenticação Node.js/Express

Este projeto é um sistema simples de autenticação com as funcionalidades:
- Login
- Cadastro
- Recuperação e redefinição de senha

## Como rodar

1. Instale as dependências:
   ```powershell
   npm install
   ```
2. Inicie o servidor:
   ```powershell
   node index.js
   ```
3. Acesse no navegador: [http://localhost:3000](http://localhost:3000)

## Estrutura
- `index.js`: servidor Express e lógica principal
- `views/`: páginas HTML (EJS)
- `public/style.css`: CSS básico
- `users.json`: arquivo gerado para simular banco de dados

## Observações
- O envio de e-mail é simulado, exibindo o link de redefinição na tela.
- O sistema é apenas para fins didáticos.
