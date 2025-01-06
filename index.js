import cors from 'cors';
import mongoose from 'mongoose';
import User from './models/User.js';
import Post from './models/Post.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import express from 'express';
import dotenv from 'dotenv';

dotenv.config();

// Initialize Express app
const app = express();

const uploadMiddleware = multer({ dest: 'uploads/' });
const salt = bcrypt.genSaltSync(10);
const secret = 'secret_key';

app.use(cors({ credentials: true, origin: 'https://story-hub1.vercel.app' }));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(path.join(path.resolve(), 'uploads')));

// Serve frontend static files
const __dirname = path.resolve(); // Handle __dirname in ES module
app.use(express.static(path.join(__dirname, 'build')));

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error.message);
  });

// API Routes
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = bcrypt.hashSync(password, salt);
    const userDoc = await User.create({ username, password: hashedPassword });
    res.json(userDoc);
  } catch (error) {
    console.error(error);
    res.status(400).json(error.message);
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.findOne({ username });
    if (!userDoc) return res.status(400).json('Invalid credentials');

    const passOk = bcrypt.compareSync(password, userDoc.password);
    if (!passOk) return res.status(400).json('Invalid credentials');

    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) throw err;
      res.cookie('token', token).json({ id: userDoc._id, username });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json('Internal server error');
  }
});

app.get('/profile', (req, res) => {
  const { token } = req.cookies;
  jwt.verify(token, secret, {}, (err, info) => {
    if (err) return res.status(401).json('Unauthorized');
    res.json(info);
  });
});

app.post('/logout', (req, res) => {
  res.cookie('token', '').json('Logged out');
});

app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
  const { originalname } = req.file;
  const ext = originalname.split('.').pop();
  const newPath = `${req.file.path}.${ext}`;
  fs.renameSync(req.file.path, newPath);

  const { token } = req.cookies;
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(401).json('Unauthorized');
    const { title, summary, content } = req.body;
    try {
      const postDoc = await Post.create({
        title,
        summary,
        content,
        cover: newPath,
        author: info.id,
      });
      res.json(postDoc);
    } catch (error) {
      console.error(error);
      res.status(500).json('Internal server error');
    }
  });
});

app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
  let newPath = null;
  if (req.file) {
    const { originalname, path: filePath } = req.file;
    const ext = originalname.split('.').pop();
    newPath = `${filePath}.${ext}`;
    fs.renameSync(filePath, newPath);
  }

  const { token } = req.cookies;
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(401).json('Unauthorized');
    const { id, title, summary, content } = req.body;

    try {
      const postDoc = await Post.findById(id);
      if (String(postDoc.author) !== String(info.id)) {
        return res.status(403).json('You are not the author');
      }
      postDoc.title = title;
      postDoc.summary = summary;
      postDoc.content = content;
      postDoc.cover = newPath || postDoc.cover;
      await postDoc.save();
      res.json(postDoc);
    } catch (error) {
      console.error(error);
      res.status(500).json('Internal server error');
    }
  });
});

app.get('/post', async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('author', ['username'])
      .sort({ createdAt: -1 })
      .limit(20);
    res.json(posts);
  } catch (error) {
    console.error(error);
    res.status(500).json('Internal server error');
  }
});

app.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const postDoc = await Post.findById(id).populate('author', ['username']);
    res.json(postDoc);
  } catch (error) {
    console.error(error);
    res.status(500).json('Internal server error');
  }
});

// Serve frontend for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

// Export the app for Vercel
module.exports = app;
