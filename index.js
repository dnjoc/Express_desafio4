const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
const PORT = 3000;

// Clave secreta para firmar el JWT (debe mantenerse segura)
const SECRET_KEY = process.env.JWT_SECRET || 'tu_secreta_clave';

// Middleware para parsear el cuerpo de las solicitudes
app.use(bodyParser.json());

// Conexión a MongoDB
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/desafio4';

mongoose.connect(MONGO_URI)
.then(() => {
  console.log('Conectado a MongoDB');
})
.catch(err => {
  console.error('Error al conectar a MongoDB:', err.message);
});

// Modelo de ejemplo
const UsuarioSchema = new mongoose.Schema({
  nombre: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const Usuario = mongoose.model('Usuario', UsuarioSchema);

// Ruta para crear un usuario
app.post('/usuarios', async (req, res) => {
  const { nombre, username, email, password } = req.body;

  try {
    // Verificar si el nombre de usuario ya existe
    const existingUser = await Usuario.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'El nombre de usuario ya existe' });
    }

    const nuevoUsuario = new Usuario({ nombre, username, email, password });
    await nuevoUsuario.save();
    res.status(201).json({ message: 'Usuario creado', usuario: nuevoUsuario });
  } catch (err) {
    console.error('Error al crear el usuario:', err.message);
    res.status(500).json({ error: 'Error al crear el usuario' });
  }
});

// Ruta para obtener usuarios
app.get('/usuarios', async (req, res) => {
  try {
    const usuarios = await Usuario.find();
    res.json(usuarios);
  } catch (err) {
    console.error('Error al obtener usuarios:', err.message);
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

// Ruta de login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Buscar usuario en la base de datos
    const user = await Usuario.findOne({ username, password });

    if (!user) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    // Creación del token JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username }, // Payload
      SECRET_KEY, // Clave secreta
      { expiresIn: '1m' } // Tiempo de expiración
    );

    // Respuesta con el token
    res.json({ token, redirect: '/dashboard' });
  } catch (err) {
    console.error('Error al iniciar sesión:', err.message);
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
});

// Middleware para verificar el JWT
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: 'No se proporcionó un token' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded; // Guardar los datos del usuario en la solicitud
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Token inválido o expirado', redirect: '/login' });
  }
};

// Ruta protegida de dashboard
app.get('/dashboard', verifyToken, (req, res) => {
  res.json({ message: 'Acceso autorizado', data: req.user });
});

// Ruta protegida de detalle
app.get('/detail/:id', verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    const user = await Usuario.findById(id);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.json({ message: `Información del detalle para el ID ${id} nombre de usuario: ${user.username}`, data: req.user });
  } catch (err) {
    console.error('Error al obtener el detalle del usuario:', err.message);
    res.status(500).json({ error: 'Error al obtener el detalle del usuario' });
  }
});

// Inicia el servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
