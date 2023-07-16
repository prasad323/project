
const bcrypt = require('bcrypt')
const express = require('express')
const jwt = require('jsonwebtoken')
const mongoose=require('mongoose')

// Create an Express application
const app = express();

// Set up MongoDB connection

mongoose.connect('mongodb://localhost/latestdb', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  console.log("Database connected");
})
.catch((error) => {
  console.log("Error occurred:", error);
});


// Create a user schema and model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
});

const User = mongoose.model('User', userSchema);

// Set up middleware to parse JSON request bodies
app.use(express.json());

// Signup endpoint
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

  
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
    });

    // Save the user to the database
    await newUser.save();

    res.status(200).json({ message: 'Signup successful' });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req , res)=> {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate a new Access token
    const accessToken = jwt.sign({ userId: user._id }, 'your-access-token-secret', { expiresIn: '120s' });


    const refreshToken = jwt.sign({ userId: user._id }, 'your-refresh-token-secret');

    res.status(200).json({ accessToken, refreshToken });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
})

// Refresh token endpoint
app.post('/refresh-token', (req, res) => {
  try {
    const { refreshToken } = req.body;

    jwt.verify(refreshToken, 'your-refresh-token-secret', function(err, decoded) {
      if (err) {
        // Handle verification error
        console.error(err);
      } else {
        // Refresh token is valid, access the decoded payload
        console.log(decoded);
      }
    });
    
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
}
});
// Delete user endpoint
app.delete('/delete-user/:userId', async (req, res) => {
    try {
    const { userId } = req.params;
  
await User.findByIdAndDelete(userId);

res.status(200).json({ message: 'User deleted successfully' });
} catch (error) {
res.status(500).json({ message: 'Internal server error' });
}
});

// Start the server
app.listen(3000, () => {
console.log('Server started on port 3000');
});

