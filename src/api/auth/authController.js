// src/api/auth/authController.js
import jwt from 'jsonwebtoken';
import { Router } from 'express';
import bcrypt from 'bcrypt'; // Para lidar com hashes de senha
import { User } from '../../data/mongooseModels.js'; // Importar o modelo User

const router = Router();

const secretKey = process.env.JWT_SECRET; // Chave secreta para JWT

// Função para gerar um token JWT após o login bem-sucedido
router.post('/login', async (req, res, next) => {
  try {
    // Verifique as credenciais do usuário, substitua isso com sua lógica de verificação de login
    const { username, password } = req.body;
    // Consulte seu banco de dados MongoDB para verificar as credenciais e obter informações do usuário
    // Substitua isso pela consulta real ao MongoDB
    console.log("username: ", username)
    console.log('password: ', password)
    const user = await User.findOne({ username }); // Use o modelo User aqui

    if (!user || !bcrypt.compareSync(password, user.password)) {
      // Credenciais inválidas
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    // Crie um token JWT com as informações do usuário
    const token = jwt.sign(
      {
        userId: user._id, // ID do usuário
        username: user.username,
        // Adicione outras informações do usuário que desejar
      },
      secretKey,
      {
        expiresIn: '1h', // Tempo de expiração do token
      }
    );

    // Retorne o token JWT
    console.log("token: ", token)
    return res.json({ token });
  } catch (error) {
    next(error);
  }
});

// Função para fazer logout (não é estritamente necessário para JWT, mas pode ser usado para invalidar tokens)
router.post('/logout', (req, res) => {
  // Você pode implementar a lógica de logout aqui
  // Você pode adicionar os tokens à lista negra ou fazer outras ações
  res.json({ message: 'Logout bem-sucedido' });
});

router.post('/generate-token', (req, res, next) => {
    try {
      // Aqui, você pode incluir quaisquer informações que desejar no token
      const data = {
        userId: 'any-unique-id',
        role: 'guest',
      };
  
      // Crie um token JWT com as informações fornecidas
      const token = jwt.sign(data, secretKey, {
        expiresIn: '1h', // Tempo de expiração do token (1 hora, por exemplo)
      });

        console.log("token: ", token)
  
      return res.json({ token });
    } catch (error) {
      next(error);
    }
  });
  

// Função para registrar um novo usuário
router.post('/signup', async (req, res, next) => {
    try {
      const { username, password } = req.body;
  
      // Verifique se o usuário já existe no banco de dados
      const existingUser = await User.findOne({ username });
  
      if (existingUser) {
        return res.status(400).json({ message: 'Nome de usuário já em uso' });
      }
  
      // Criptografe a senha
      const hashedPassword = bcrypt.hashSync(password, 10);
  
      // Crie o novo usuário
      const newUser = new User({
        username,
        password: hashedPassword,
      });
  
      await newUser.save();

        console.log("newUser: ", newUser)
  
      // Gere um token JWT para o novo usuário
        const token = jwt.sign(
            {
            userId: newUser._id,
            username: newUser.username,
            },
            secretKey,
            {
            expiresIn: '1h',
            }
        );

      console.log("token111: ", token)
  
      // Retorne o token JWT
      return res.json({ token });
    } catch (error) {
      next(error);
    }
  });
  

export default router;
