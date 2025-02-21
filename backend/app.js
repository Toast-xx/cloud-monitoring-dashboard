const express = require('express');
const { Client } = require('pg');
const { DynamoDBClient, PutItemCommand } = require('@aws-sdk/client-dynamodb');
const axios = require('axios');
const { Kafka, Partitioners } = require('kafkajs');
const dotenv = require('dotenv');
const { CloudWatchClient, GetMetricDataCommand } = require('@aws-sdk/client-cloudwatch');
const { MetricServiceClient } = require('@google-cloud/monitoring');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const cors = require('cors');
const bcrypt = require('bcrypt');
const AWS = require('aws-sdk');

dotenv.config(); // Load environment variables

const app = express();
const port = 5000;

app.use(express.json());
app.use(cors({
  origin: 'http://localhost:3000', // Allow requests from the frontend
  credentials: true // Allow cookies to be sent with requests
}));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false, // Change to false to avoid creating sessions for unauthenticated users
  cookie: { secure: false } // Set to true if using HTTPS
}));
app.use(passport.initialize());
app.use(passport.session());

// PostgreSQL Connection Setup
const db = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
db.connect()
  .then(() => console.log('PostgreSQL connected successfully'))
  .catch(err => console.error('PostgreSQL connection error:', err));

// Registration endpoint
app.post('/api/auth/register', async (req, res) => {
  console.log('Received registration request:', req.body);
  const { firstName, lastName, email, newPassword } = req.body;

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    console.log('Hashed password:', hashedPassword);

    // Save the user to the database
    const query = 'INSERT INTO users (first_name, last_name, email, password) VALUES ($1, $2, $3, $4)';
    await db.query(query, [firstName, lastName, email, hashedPassword]);
    console.log('User registered successfully');

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  console.log('Received login request:', req.body);
  const { email, password } = req.body;

  try {
    // Retrieve the user from the database
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await db.query(query, [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    req.login(user, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.json({ message: 'Login successful' });
    });
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Configure Passport.js
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'http://localhost:5000/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  // Save the user profile or accessToken in your database if needed
  console.log('Google profile:', profile);
  return done(null, profile);
}));

passport.serializeUser((user, done) => {
  console.log('Serialize user:', user);
  done(null, user);
});

passport.deserializeUser((user, done) => {
  console.log('Deserialize user:', user);
  done(null, user);
});

// Routes
app.get('/auth/google', (req, res, next) => {
  console.log('Starting Google OAuth flow');
  next();
}, passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  console.log('Successful authentication');
  res.redirect('http://localhost:3000/oauth2callback'); // Adjust the URL to your frontend
});

app.get('/auth/status', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ authenticated: true, user: req.user });
  } else {
    res.json({ authenticated: false });
  }
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Internal server error' });
    }
    res.redirect('/');
  });
});

// AWS CloudWatch Metrics Endpoint
app.get('/metrics/aws', async (req, res) => {
  console.log('Received request for AWS metrics');
  const { accessToken } = req.query;
  // Validate accessToken if needed

  AWS.config.update({ region: 'us-east-1' });

  const cw = new AWS.CloudWatch({ apiVersion: '2010-08-01' });

  const params = {
    Dimensions: [
      {
        Name: 'LogGroupName',
        Value: 'your-log-group-name'
      },
    ],
    MetricName: 'IncomingLogEvents',
    Namespace: 'AWS/Logs',
  };

  cw.listMetrics(params, (err, data) => {
    if (err) {
      console.error('Error fetching AWS metrics:', err);
      res.status(500).json({ error: 'Error fetching AWS metrics' });
    } else {
      res.json(data.Metrics);
    }
  });
});

// Google Cloud Monitoring Metrics Endpoint
const monitoring = new MetricServiceClient({
  keyFilename: 'path/to/cloud-monitoring-dashboard-f2147c7853bf.json'
});

app.get('/metrics/google', async (req, res) => {
  console.log('Received request for Google metrics');
  const { accessToken } = req.query;
  // Validate accessToken if needed

  const projectId = 'cloud-monitoring-dashboard';
  const request = {
    name: monitoring.projectPath(projectId),
    filter: 'metric.type="compute.googleapis.com/instance/cpu/utilization"',
    interval: {
      startTime: { seconds: Date.now() / 1000 - 3600 },
      endTime: { seconds: Date.now() / 1000 }
    }
  };

  try {
    const [timeSeries] = await monitoring.listTimeSeries(request);
    res.json(timeSeries);
  } catch (err) {
    console.error('Error fetching Google metrics:', err);
    res.status(500).json({ error: 'Error fetching Google metrics' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});