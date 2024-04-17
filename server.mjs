import bcrypt from "bcrypt";
import express from "express";
import jwt from "jsonwebtoken";
import mysql from "mysql";
import swaggerUI from "swagger-ui-express";
import winston from "winston";
import swaggerSpec from "./swagger.js";

const saltRounds = 10;
const app = express();
app.use(express.json());
// Jwt secret
const secret = "secret";

const logger = winston.createLogger({
  transports: [
    // Save the log in the file server.log
    new winston.transports.File({ filename: "server.log" }),
    // Show the log in the console
    new winston.transports.Console(),
  ],
});

const mysqlClient = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Temporal2021+",
  database: "securityWeb",
});

mysqlClient.connect((err) => {
  if (err) {
    logger.error("Error connecting to database:", err);
    return;
  }
  logger.info("Conexión exitosa a la base de datos");
});

app.use("/api-docs", swaggerUI.serve, swaggerUI.setup(swaggerSpec));

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *       500:
 *         description: Error occurred while registering user or hashing password
 */
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      logger.error("Error hashing password:", err);
      res.status(500).send("Error hashing password");
      return;
    }

    const query = `INSERT INTO users (username, password) VALUES ('${username}', '${hash}')`;

    mysqlClient.query(query, (err, result) => {
      if (err) {
        logger.error("Error registering user:", err);
        res.status(500).send("Error registering user");
        return;
      }

      res.status(200).send("User registered successfully");
    });
  });
});

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Log in a user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: User logged in successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       401:
 *         description: Invalid password or user not found
 *       500:
 *         description: Error occurred while logging in or comparing passwords
 */
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const query = `SELECT * FROM users WHERE username = '${username}'`;

  mysqlClient.query(query, (err, result) => {
    if (err) {
      logger.error("Error logging in:", err);
      res.status(500).send("Error logging in");
      return;
    }

    if (result.length === 0) {
      res.status(401).send("User not found");
      return;
    }

    const user = result[0];

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        logger.error("Error comparing passwords:", err);
        res.status(500).send("Error comparing passwords");
        return;
      }

      if (result) {
        // Return a json with the token wich includes the username, expiration time, id and secret
        const token = jwt.sign({ id: user.user_id }, secret, {
          expiresIn: "1h",
        });
        res.status(200).json({ token });
      } else {
        res.status(401).send("Invalid password");
      }
    });
  });
});

// Middleware to check if the token is valid
const checkToken = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) {
    res.status(401).send("Token not provided");
    return;
  }

  jwt.verify(token, secret, (err, decoded) => {
    if (err) {
      res.status(401).send("Invalid token");
      return;
    }

    req.user = decoded;
    next();
  });
};

/**
 * @swagger
 * /courses:
 *   get:
 *     summary: Get courses for a user
 *     tags: [Courses]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of courses
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   course_id:
 *                     type: integer
 *                   coursename:
 *                     type: string
 *                   total:
 *                     type: integer
 *       401:
 *         description: User not found
 *       500:
 *         description: Error occurred while getting courses
 */
app.get("/courses", checkToken, (req, res) => {
  // Token from the header
  const token = req.headers["authorization"];
  // Decoded token
  const decoded = jwt.decode(token);
  // Get the user id from the decoded token
  const user_id = decoded.id;

  if (!user_id) {
    res.status(401).send("User not found");
    return;
  }

  const query = `SELECT c.course_id, c.coursename, uc.total  FROM courses c JOIN user_courses uc ON c.course_id = uc.course_id WHERE uc.user_id = ${user_id}`;

  // If the user is not found return 401
  if (!user_id) {
    res.status(401).send("User not found");
    return;
  }

  mysqlClient.query(query, (err, result) => {
    if (err) {
      logger.error("Error getting courses:", err);
      res.status(500).send("Error getting courses");
      return;
    }

    res.status(200).json(result);
  });
});

/**
 * @swagger
 * /highest-course:
 *   get:
 *     summary: Get the course with the highest total for a user
 *     tags: [Courses]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Course with the highest total
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 coursename:
 *                   type: string
 *                 total:
 *                   type: integer
 *       401:
 *         description: User not found
 *       500:
 *         description: Error occurred while getting the highest course
 */
app.get("/highest-course", checkToken, (req, res) => {
  const token = req.headers["authorization"];
  const decoded = jwt.decode(token);
  const user_id = decoded.id;
  const query = `SELECT c.coursename, uc.total FROM courses c 
  JOIN user_courses uc ON uc.course_id = c.course_id WHERE uc.total = (SELECT MAX(total) FROM user_courses WHERE uc.user_id = ${user_id});`;

  if (!user_id) {
    res.status(401).send("User not found");
    return;
  }

  mysqlClient.query(query, (err, result) => {
    if (err) {
      logger.error("Error getting highest course:", err);
      res.status(500).send("Error getting highest course");
      return;
    }

    res.status(200).json(result);
  });
});

/**
 * @swagger
 * /lower-course:
 *   get:
 *     summary: Get the course with the lowest total for a user
 *     tags: [Courses]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Course with the lowest total
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 coursename:
 *                   type: string
 *                 total:
 *                   type: integer
 *       401:
 *         description: User not found
 *       500:
 *         description: Error occurred while getting the lowest course
 */
app.get("/lower-course", checkToken, (req, res) => {
  const token = req.headers["authorization"];
  const decoded = jwt.decode(token);
  const user_id = decoded.id;
  const query = `SELECT c.coursename, uc.total FROM courses c 
  JOIN user_courses uc ON uc.course_id = c.course_id WHERE uc.total = (SELECT MIN(total) FROM user_courses WHERE uc.user_id = ${user_id});`;

  if (!user_id) {
    res.status(401).send("User not found");
    return;
  }

  mysqlClient.query(query, (err, result) => {
    if (err) {
      logger.error("Error getting lower course:", err);
      res.status(500).send("Error getting lower course");
      return;
    }

    res.status(200).json(result);
  });
});

app.listen(3000, () => {
  logger.info("Servidor iniciado en el puerto 3000 🚀");
});
