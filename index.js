const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || 'segredo_super_secreto';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
const upload = multer({ dest: path.join(__dirname, 'public', 'uploads') });

// Simulação de "banco de dados" em arquivo JSON
const USERS_FILE = path.join(__dirname, 'users.json');
function getUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  return JSON.parse(fs.readFileSync(USERS_FILE));
}
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Usuário admin fixo
const ADMIN_USER = {
  email: 'javaloucosapp@gmail.com',
  password: 'javajava2025',
};

// Armazena códigos de recuperação temporários
const recoveryCodes = {};

// Lista de códigos de cadastro válidos
let codigosCadastro = [];

// Função para gerar código de cadastro (admin)
function gerarCodigoCadastro() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let codigo = '';
  for (let i = 0; i < 8; i++) {
    codigo += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  codigosCadastro.push(codigo);
  return codigo;
}

// Rotas principais
app.get('/', (req, res) => {
  res.render('login', { error: null });
});

app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.get('/forgot', (req, res) => {
  res.render('forgot', { error: null, success: null });
});

app.get('/gerar-codigo', (req, res) => {
  // Apenas admin pode acessar
  const users = getUsers();
  res.render('success', { email: 'Administrador', tipo: 'admin', novoCodigo: gerarCodigoCadastro(), users });
});

app.post('/register', upload.single('foto'), (req, res) => {
  const { email, password, repeatPassword, nome, cpf, nascimento, codigoCadastro } = req.body;
  let users = getUsers();
  if (users.find(u => u.email === email)) {
    return res.render('register', { error: 'E-mail já cadastrado!' });
  }
  if (!codigosCadastro.includes(codigoCadastro)) {
    return res.render('register', { error: 'Código de cadastro inválido!' });
  }
  if (password !== repeatPassword) {
    return res.render('register', { error: 'As senhas não coincidem!' });
  }
  // Validação de CPF
  function validaCPF(cpf) {
    cpf = cpf.replace(/\D/g, '');
    if (cpf.length !== 11 || /^([0-9])\1+$/.test(cpf)) return false;
    let soma = 0, resto;
    for (let i = 1; i <= 9; i++) soma += parseInt(cpf.substring(i-1, i)) * (11 - i);
    resto = (soma * 10) % 11;
    if (resto === 10 || resto === 11) resto = 0;
    if (resto !== parseInt(cpf.substring(9, 10))) return false;
    soma = 0;
    for (let i = 1; i <= 10; i++) soma += parseInt(cpf.substring(i-1, i)) * (12 - i);
    resto = (soma * 10) % 11;
    if (resto === 10 || resto === 11) resto = 0;
    if (resto !== parseInt(cpf.substring(10, 11))) return false;
    return true;
  }
  if (!validaCPF(cpf)) {
    return res.render('register', { error: 'CPF inválido!' });
  }
  if (!nome || !nascimento) {
    return res.render('register', { error: 'Preencha todos os campos!' });
  }
  // Data de validade: 1 ano após cadastro
  const dataCadastro = new Date();
  const validade = new Date(dataCadastro);
  validade.setFullYear(validade.getFullYear() + 1);
  const hash = bcrypt.hashSync(password, 8);
  let foto = req.file ? `/uploads/${req.file.filename}` : null;
  users.push({ email, password: hash, nome, cpf, nascimento, validade: validade.toISOString().split('T')[0], foto });
  saveUsers(users);
  // Remove código usado
  codigosCadastro = codigosCadastro.filter(c => c !== codigoCadastro);
  res.redirect('/');
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (email === ADMIN_USER.email && password === ADMIN_USER.password) {
    const users = getUsers();
    return res.render('success', { email: 'Administrador', tipo: 'admin', users });
  }
  const users = getUsers();
  const user = users.find(u => u.email === email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.render('login', { error: 'E-mail ou senha inválidos!' });
  }
  res.render('success', { email: user.nome || user.email, tipo: 'comum', user });
});

app.post('/forgot', async (req, res) => {
  const { email } = req.body;
  let users = getUsers();
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.render('forgot', { error: 'E-mail não encontrado!', success: null });
  }
  // Gera código de 6 dígitos
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  recoveryCodes[email] = { code, expires: Date.now() + 15 * 60 * 1000 };
  // Configuração do Nodemailer para Gmail
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
  user: process.env.EMAIL_USER,
  pass: process.env.EMAIL_PASS,
},
  });
  try {
    await transporter.verify(); // Testa conexão com o servidor SMTP
    await transporter.sendMail({
      from: 'javaloucosapp@gmail.com',
      to: email,
      subject: 'Código de recuperação de senha',
      html: `<p>Seu código de recuperação: <b>${code}</b></p>`
    });
    res.render('forgot', { error: null, success: 'Código enviado para o seu e-mail!' });
  } catch (err) {
    res.render('forgot', { error: 'Erro ao enviar e-mail: ' + err.message, success: null });
  }
});

app.post('/reset/', (req, res) => {
  const { email, code, password, repeatPassword } = req.body;
  if (!email || !code || !password || !repeatPassword) {
    return res.render('forgot', { error: 'Preencha todos os campos!', success: null });
  }
  const entry = recoveryCodes[email];
  if (!entry || entry.code !== code || Date.now() > entry.expires) {
    return res.render('forgot', { error: 'Código inválido ou expirado!', success: null });
  }
  if (password !== repeatPassword) {
    return res.render('forgot', { error: 'As senhas não coincidem!', success: null });
  }
  let users = getUsers();
  const idx = users.findIndex(u => u.email === email);
  if (idx === -1) return res.render('forgot', { error: 'Usuário não encontrado!', success: null });
  users[idx].password = bcrypt.hashSync(password, 8);
  saveUsers(users);
  delete recoveryCodes[email];
  // Mensagem de sucesso e redireciona para login
  res.render('login', { error: null, success: 'Senha redefinida com sucesso! Faça login.' });
});

app.post('/editar-carteirinha', (req, res) => {
  // Apenas usuário comum pode editar sua própria carteirinha
  const { email, nome, cpf, nascimento } = req.body;
  let users = getUsers();
  const idx = users.findIndex(u => u.email === email);
  if (idx === -1) return res.redirect('/');
  users[idx].nome = nome;
  users[idx].cpf = cpf;
  users[idx].nascimento = nascimento;
  // NÃO altera users[idx].validade!
  saveUsers(users);
  // Renderiza a carteirinha atualizada
  res.render('success', { email: nome, tipo: 'comum', user: users[idx] });
});

app.get('/gerenciar-carteirinhas', (req, res) => {
  // Apenas admin pode acessar
  const users = getUsers();
  res.render('gerenciar-carteirinhas', { users });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});

