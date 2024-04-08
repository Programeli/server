//Express is a fast, unopinionated, minimalist web framework for Node.js.
const express = require('express');

//The mysql module is used to interact with MySQL databases. 
const mysql = require('mysql');

//The body-parser middleware is used to parse the incoming request body in a format such as JSON, URL-encoded, or multipart. 
//It extracts the body data and makes it accessible in the req.body object.
const bodyParser = require('body-parser');

//CORS is a security feature implemented by web browsers to restrict web pages from making requests to a different domain than the one that served the web page.
const cors = require('cors');

//bcrypt is a password hashing library for Node.js.
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3001;

// Create a MySQL connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'final-react',
});

// Connect to MySQL database
connection.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

app.use(bodyParser.json());
app.use(cors());

// Signup endpoint
app.post('/register', async (req, res) => {
  const {firstname, lastname, username, email, password } = req.body;

  // Validate data (you may want to add more robust validation)
  if (!username || !email || !password || !firstname || !lastname) {
    return res.status(400).json({ error: 'Incomplete data' });
  }

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 15);

    // Insert user into the database
    const insertUserQuery = 'INSERT INTO users (firstname, lastname, username, email, password) VALUES (?, ?, ?, ?, ?)';
    const values = [firstname, lastname, username, email, hashedPassword];

    connection.query(insertUserQuery, values, (error, results) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'Internal server error' });
      }

      res.status(201).json({ message: 'User registered successfully' });
    });
  } catch (error) {
    console.error('Error hashing password on the server:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


//Log in endpoint
app.post('/log-in', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Query the database to check if the user exists
    const getUserQuery = `SELECT * FROM users WHERE username = ?`;
    connection.query(getUserQuery, [username], async (error, results) => {
      if (error) {
        console.error('Error executing database query:', error);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (results.length === 0) {
        // User not found or invalid username/password
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      const user = results[0];

      if (!user || !user.password) {
        // Invalid user object or missing password
        return res.status(500).json({ error: 'Invalid user object in the database' });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        // Incorrect password
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      // Authentication successful
      return res.status(200).json({ message: 'Login successful' });
    });
  } catch (error) {
    // Handle database query error
    console.error('Error executing database query:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
