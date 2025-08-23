const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

require('dotenv').config();

const { createClient } = require('@supabase/supabase-js');
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || 'segredo_super_secreto';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
const upload = multer({ dest: path.join(__dirname, 'public', 'uploads') });

// Usuário admin fixo
const ADMIN_USER = {
  email: process.env.ADMIN_EMAIL,
  password: process.env.ADMIN_PASS
};

// // Função para gerar código de cadastro (admin)
function gerarCodigoCadastro() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let codigo = '';
  for (let i = 0; i < 8; i++) {
    codigo += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  //codigosCadastro.push(codigo);
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

app.get('/gerar-codigo', async (req, res) => {
  const novoCodigo = gerarCodigoCadastro();
  await supabase.from('codigos_cadastro').insert([{ codigo: novoCodigo }]);
  const { data: users } = await supabase.from('usuarios').select('*');
  res.render('success', { email: 'Administrador', tipo: 'admin', novoCodigo, users });
});

app.post('/register', upload.single('foto'), async (req, res) => {
  const { email, password, repeatPassword, nome, cpf, nascimento, codigoCadastro } = req.body;

  // Busca se já existe usuário no Supabase
  const { data: users } = await supabase.from('usuarios').select('email').eq('email', email);
  if (users && users.length > 0) {
    return res.render('register', { error: 'E-mail já cadastrado!' });
  }

  // Validação do código de cadastro
  const { data: codigos } = await supabase.from('codigos_cadastro').select('*').eq('codigo', codigoCadastro).eq('usado', false);
  if (!codigos || codigos.length === 0) {
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

  // Upload da foto para Supabase Storage (opcional)
  let fotoUrl = null;
  if (req.file) {
    const ext = path.extname(req.file.originalname) || '.jpg';
    const supaFileName = `${Date.now()}_${email.replace(/[^a-zA-Z0-9]/g, '')}${ext}`;
    const fileBuffer = fs.readFileSync(req.file.path);

    const { error: uploadError } = await supabase
      .storage
      .from('fotos')
      .upload(supaFileName, fileBuffer, {
        contentType: req.file.mimetype,
        upsert: true
      });


    if (!uploadError) {
      const { data: urlData } = supabase.storage.from('fotos').getPublicUrl(supaFileName);
      fotoUrl = urlData.publicUrl;
    }

    // Remove arquivo local
    fs.unlinkSync(req.file.path);
  }

  // Insere usuário no Supabase
  const { error } = await supabase
    .from('usuarios')
    .insert([{
      email,
      password: bcrypt.hashSync(password, 8),
      nome,
      cpf,
      nascimento,
      validade: validade.toISOString().split('T')[0],
      foto: fotoUrl
    }]);

  if (error) {
    return res.render('register', { error: 'Erro ao cadastrar usuário!' });
  }

  // Marca o código como usado
  await supabase.from('codigos_cadastro').update({ usado: true }).eq('codigo', codigoCadastro);

  res.redirect('/');
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Admin fixo
  if (email === ADMIN_USER.email && password === ADMIN_USER.password) {
    // Busca todos os usuários do Supabase para o admin
    const { data: users, error } = await supabase.from('usuarios').select('*');
    if (error) return res.render('login', { error: 'Erro ao buscar usuários!' });
    return res.render('success', { email: 'Administrador', tipo: 'admin', users });
  }

  // Busca usuário comum no Supabase
  const { data: users, error } = await supabase.from('usuarios').select('*').eq('email', email);
  const user = users && users[0];
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.render('login', { error: 'E-mail ou senha inválidos!' });
  }
  res.render('success', { email: user.nome || user.email, tipo: 'comum', user });
});

app.post('/forgot', async (req, res) => {
  const { email } = req.body;

  // Busca usuário no Supabase
  const { data: users } = await supabase.from('usuarios').select('id,email').eq('email', email);
  const user = users && users[0];
  if (!user) {
    return res.render('forgot', { error: 'E-mail não encontrado!', success: null });
  }

  // Gera código de 6 dígitos
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiracao = new Date(Date.now() + 15 * 60 * 1000).toISOString();

  // Salva código na tabela recuperacao_senha
  await supabase.from('recuperacao_senha').insert([{
    usuario_id: user.id,
    codigo: code,
    expiracao
  }]);

  // Configuração do Nodemailer para Gmail
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  try {
    await transporter.verify();
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

app.post('/reset/', async (req, res) => {
  const { email, code, password, repeatPassword } = req.body;
  if (!email || !code || !password || !repeatPassword) {
    return res.render('forgot', { error: 'Preencha todos os campos!', success: null });
  }

  // Busca usuário no Supabase
  const { data: users } = await supabase.from('usuarios').select('id,email').eq('email', email);
  const user = users && users[0];
  if (!user) return res.render('forgot', { error: 'Usuário não encontrado!', success: null });

  // Busca código de recuperação
  const { data: tokens } = await supabase
    .from('recuperacao_senha')
    .select('*')
    .eq('usuario_id', user.id)
    .eq('codigo', code)
    .order('criado_em', { ascending: false });
  const token = tokens && tokens[0];
  if (!token || new Date(token.expiracao) < new Date()) {
    return res.render('forgot', { error: 'Código inválido ou expirado!', success: null });
  }
  if (password !== repeatPassword) {
    return res.render('forgot', { error: 'As senhas não coincidem!', success: null });
  }

  // Atualiza senha no Supabase
  await supabase.from('usuarios').update({ password: bcrypt.hashSync(password, 8) }).eq('id', user.id);
  await supabase.from('recuperacao_senha').delete().eq('id', token.id);

  res.render('login', { error: null, success: 'Senha redefinida com sucesso! Faça login.' });
});

app.post('/editar-carteirinha', upload.single('foto'), async (req, res) => {
  const { email, nome, cpf, nascimento } = req.body;

  // Busca usuário
  const { data: users, error: userError } = await supabase.from('usuarios').select('*').eq('email', email);
  const user = users && users[0];

  if (!user) return res.redirect('/');

  // Atualiza foto se enviada
  let fotoUrl = user.foto;
  if (req.file) {

    // Remove foto antiga do Supabase Storage se existir
    if (user.foto) {
      const prefix = "/object/public/fotos/";
      const oldFotoPath = user.foto.includes(prefix) ? user.foto.split(prefix)[1] : user.foto;
      const { error: removeError } = await supabase.storage.from('fotos').remove([oldFotoPath]);
    }

    // Gera novo nome
    const ext = path.extname(req.file.originalname) || '.jpg';
    const supaFileName = `${Date.now()}_${email.replace(/[^a-zA-Z0-9]/g, '')}${ext}`;

    // Lê arquivo em buffer
    const fileBuffer = fs.readFileSync(req.file.path);

    const { error: uploadError } = await supabase
      .storage
      .from('fotos')
      .upload(supaFileName, fileBuffer, {
        contentType: req.file.mimetype,
        upsert: true
      });

    if (uploadError) {
    } else {
      const { data: urlData } = supabase.storage.from('fotos').getPublicUrl(supaFileName);
      fotoUrl = urlData.publicUrl;
    }

    // Remove arquivo local
    fs.unlinkSync(req.file.path);
  } else {
  }

  // Atualiza dados
  const { error: updateError } = await supabase.from('usuarios').update({
    nome,
    cpf,
    nascimento,
    foto: fotoUrl
  }).eq('email', email);

  // Busca atualizado
  const { data: updatedUsers, error: updatedError } = await supabase.from('usuarios').select('*').eq('email', email);

  res.render('success', { email, tipo: 'comum', user: updatedUsers[0] });
});


app.get('/gerenciar-carteirinhas', async (req, res) => {
  // Apenas admin pode acessar
  const { data: users, error } = await supabase.from('usuarios').select('*');
  if (error) return res.render('gerenciar-carteirinhas', { users: [] });
  res.render('gerenciar-carteirinhas', { users });
});

app.post('/admin/excluir-carteirinha', async (req, res) => {
  const { email } = req.body;

  // Busca usuário no Supabase
  const { data: users } = await supabase.from('usuarios').select('id,foto').eq('email', email);
  const user = users && users[0];
  if (!user) return res.json({ success: false, message: 'Usuário não encontrado.' });

  // Remove foto do Supabase Storage se existir
  if (user.foto) {
    const fotoPath = user.foto.split('/').pop(); // pega o nome do arquivo
    await supabase.storage.from('fotos').remove([fotoPath]);
  }

  // Remove usuário do banco
  await supabase.from('usuarios').delete().eq('id', user.id);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});

