const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


const app = express();
app.use(express.json()); // Parse JSON bodies automatically

const roles = {
    Admin: 'admin',
    User: 'user',
    Guest: 'guest'
};

const users = []; // Temporary storage for users, since we aren't using a database


app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { username, password: hashedPassword, role };
    users.push(user); // Store the user in memory

    res.status(201).json({ message: 'User registered' });
});


app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    // Check if the user exists and if the password is correct
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Create a token with the user's username and role
    const token = jwt.sign({ username: user.username, role: user.role }, 'your_jwt_secret');
    res.json({ token });
});


const authorize = (roles) => {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, 'your_jwt_secret');
            if (!roles.includes(decoded.role)) {
                return res.status(403).json({ message: 'Forbidden' });
            }
            req.user = decoded; // Store user details in request
            next(); // Allow the request to proceed
        } catch (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }
    };
};


app.get('/public', (req, res) => {
    res.send('Public route accessible to everyone');
});

app.get('/user', authorize([roles.User, roles.Admin]), (req, res) => {
    res.send('User route accessible to User and Admin');
});

app.get('/admin', authorize([roles.Admin]), (req, res) => {
    res.send('Admin route accessible to Admin only');
});


app.listen(3000, () => {
    console.log('Server running on port 3000');
});