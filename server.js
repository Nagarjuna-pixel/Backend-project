require('dotenv').config();
const express = require('express');
const { getDesignations } = require('./Training');
const { getDepartment } = require('./TrainingDepartment');
const cors = require('cors');
const oracledb = require('oracledb');
const crypto = require('crypto');
const session = require('express-session');
const { connectDb_dev } = require('./database');
const bodyParser = require('body-parser');
const winston = require('winston');

const secret = crypto.randomBytes(64).toString('hex');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const fileUpload = require('express-fileupload');

const app = express();
const port = process.env.PORT || 5000;

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console(),
  ],
});

// Initialize Oracle client
try {
  oracledb.initOracleClient({ libDir: 'E:\\instantclient' });
} catch (err) {
  console.error('Oracle client initialization failed:', err);
  process.exit(1);
}

app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://192.168.90.221:3000',
    'http://localhost:8081',
    "http://192.168.90.221:5000"
  ],
  // origin:true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// app.use(cors());
app.use(bodyParser.json({
  strict: true,
  type: 'application/json',
}));

app.use(session({
  secret: secret,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 },
}));

// Existing endpoints (unchanged except /session)
app.use(session({
  secret: secret,
  resave: false,
  saveUninitialized: false, // Changed to false for better security
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // Only use secure in production
    httpOnly: true, 
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax' // Helps prevent CSRF attacks
  },
}));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = "uploads/medical-certificates/";
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() !== '.pdf') {
      return cb(new Error('Only PDF files are allowed'));
    }
    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Leave Request Submission Endpoint
app.post('/apply-leave', upload.single('medicalCertificate'), async (req, res) => {
  let connection;
  
  try {
    // Extract form data from request
    const {
      name,
      employeeId,
      leaveType,
      department,
      fromDate,
      toDate,
      reason,
      sessionFrom,
      sessionTo,
    } = req.body;

    const medicalCertificatePath = req.file ? req.file.path : null;

    // Validate required fields
    if (!name || !employeeId || !leaveType || !department || !fromDate || !toDate || !reason) {
      return res.status(400).json({
        success: false,
        message: 'All required fields must be provided'
      });
    }

    connection = await connectDb_dev();

    // Generate unique ID
    const idResult = await connection.execute(
      'SELECT NVL(MAX(ID), 0) + 1 as NEW_ID FROM LEAVE_REQUESTS_DUMMY',
      [],
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    const newId = idResult.rows[0].NEW_ID;

    // Insert into LEAVE_REQUESTS_DUMMY table
    const query = `
      INSERT INTO LEAVE_REQUESTS_DUMMY (
         NAME, EMPLOYEE_ID, LEAVE_TYPE, DEPARTMENT,
        FROM_DATE, TO_DATE, REASON, SESSION_FROM, SESSION_TO,
        MEDICAL_CERTIFICATE_PATH
      ) VALUES (
         :name, :employeeId, :leaveType, :department,
        TO_DATE(:fromDate, 'YYYY-MM-DD'), TO_DATE(:toDate, 'YYYY-MM-DD'), :reason,
        :sessionFrom, :sessionTo, :medicalCertificatePath
      )
    `;

    const binds = {
      name,
      employeeId,
      leaveType,
      department,
      fromDate,
      toDate,
      reason,
      sessionFrom: sessionFrom || null,
      sessionTo: sessionTo || null,
      medicalCertificatePath 
    };

    const options = {
      autoCommit: true,
      bindDefs: {
        name: { type: oracledb.STRING, maxSize: 100 },
        employeeId: { type: oracledb.STRING, maxSize: 20 },
        leaveType: { type: oracledb.STRING, maxSize: 50 },
        department: { type: oracledb.STRING, maxSize: 100 },
        fromDate: { type: oracledb.STRING, maxSize: 10 },
        toDate: { type: oracledb.STRING, maxSize: 10 },
        reason: { type: oracledb.STRING, maxSize: 500 },
        sessionFrom: { type: oracledb.STRING, maxSize: 20 },
        sessionTo: { type: oracledb.STRING, maxSize: 20 },
        medicalCertificatePath: { type: oracledb.STRING, maxSize: 255 },
      }
    };

    await connection.execute(query, binds, options);

    res.status(200).json({
      success: true,
      message: 'Leave application submitted successfully',
      data: { id: newId }
    });

  } catch (error) {
    console.error('Error submitting leave application:', error);
    
    // Clean up uploaded file if insertion fails
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    res.status(500).json({
      success: false,
      message: 'Failed to submit leave application',
      error: error.message
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error('Error closing connection:', err);
      }
    }
  }
});

app.get('/get-leave-requests', async (req, res) => {
  let connection;

  try {
    connection = await connectDb_dev();

    const query = `
      SELECT ID, EMPLOYEE_ID, NAME, DEPARTMENT, LEAVE_TYPE, 
             TO_CHAR(FROM_DATE, 'YYYY-MM-DD') AS FROM_DATE,
             SESSION_FROM, TO_CHAR(TO_DATE, 'YYYY-MM-DD') AS TO_DATE,
             SESSION_TO, REASON, MEDICAL_CERTIFICATE_PATH
      FROM LEAVE_REQUESTS_DUMMY
    `;

    const result = await connection.execute(query, [], { outFormat: oracledb.OUT_FORMAT_OBJECT });

    res.status(200).json({
      success: true,
      data: result.rows
    });

  } catch (error) {
    console.error('Error fetching leave requests:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch leave requests',
      error: error.message
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error('Error closing connection:', err);
      }
    }
  }
});

app.get('/get-name', async (req, res) => {
  let connection;

  try {
    connection = await connectDb_dev();

    const query = `
      SELECT EPDMAA_NAME
      FROM EPDMAA_PERSONAL_DETAILS
    `;

    const result = await connection.execute(query, [], { outFormat: oracledb.OUT_FORMAT_OBJECT });

    res.status(200).json({
      success: true,
      data: result.rows
    });

  } catch (error) {
    console.error('Error fetching name requests:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch name requests',
      error: error.message
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error('Error closing connection:', err);
      }
    }
  }
});

app.get('/ping', (req, res) => {
  res.status(200).json({ message: 'Server is online' });
});

app.post('/admin-login', async (req, res) => {
  const { userId, password } = req.body;
  
  console.log('Login attempt:', userId); // Log for debugging
  
  if (!userId || !password) {
    return res.status(400).json({ message: 'User ID and password are required' });
  }

  try {
    const connection = await connectDb_dev();
    try {
      // First check if the user exists
      const result_user = await connection.execute(
        'SELECT SECMAA_USER_ID, SECMAA_NAME FROM SEC.SECMAA_USER_MASTER WHERE SECMAA_USER_ID = :userId',
        [userId],
        { outFormat: oracledb.OUT_FORMAT_OBJECT }
      );

      const rows = result_user.rows;
      
      if (rows.length === 0) {
        return res.status(401).json({ message: 'User not found' });
      }

      // Then validate the credentials
      const result = await connection.execute(
        `BEGIN
          :output := HMS.WEB_VALIDATE_USER_ACCESS_FUN(:input1, :input2);
        END;`,
        {
          input1: userId,
          input2: password,
          output: { type: oracledb.DB_TYPE_VARCHAR, dir: oracledb.BIND_OUT },
        }
      );

      if (result.outBinds.output === "SUCCESS") {
        // Store user data in session
        req.session.userId = rows[0].SECMAA_USER_ID;
        req.session.userName = rows[0].SECMAA_NAME;

        return res.status(200).json({
          message: 'Login successful',
          userId: rows[0].SECMAA_USER_ID,
          userName: rows[0].SECMAA_NAME,
        });
      } else {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
    } catch (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ message: 'Database error' });
    } finally {
      await connection.close();
    }
  } catch (error) {
    console.error('Database connection error:', error);
    return res.status(500).json({ message: 'Unable to connect to database' });
  }
});



app.post('/login', async (req, res) => {
  const { userId, password } = req.body;
  
  console.log('Login attempt:', userId); // Log for debugging
  
  if (!userId || !password) {
    return res.status(400).json({ message: 'User ID and password are required' });
  }

  try {
    const connection = await connectDb_dev();
    try {
      // First check if the user exists
      const result_user = await connection.execute(
        'SELECT SECMAA_USER_ID, SECMAA_NAME FROM SEC.SECMAA_USER_MASTER WHERE SECMAA_USER_ID = :userId',
        [userId],
        { outFormat: oracledb.OUT_FORMAT_OBJECT }
      );

      const rows = result_user.rows;
      
      if (rows.length === 0) {
        return res.status(401).json({ message: 'User not found' });
      }

      // Then validate the credentials
      const result = await connection.execute(
        `BEGIN
          :output := HMS.WEB_VALIDATE_USER_ACCESS_FUN(:input1, :input2);
        END;`,
        {
          input1: userId,
          input2: password,
          output: { type: oracledb.DB_TYPE_VARCHAR, dir: oracledb.BIND_OUT },
        }
      );

      if (result.outBinds.output === "SUCCESS") {
        // Store user data in session
        req.session.userId = rows[0].SECMAA_USER_ID;
        req.session.userName = rows[0].SECMAA_NAME;

        return res.status(200).json({
          message: 'Login successful',
          userId: rows[0].SECMAA_USER_ID,
          userName: rows[0].SECMAA_NAME,
        });
      } else {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
    } catch (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ message: 'Database error' });
    } finally {
      await connection.close();
    }
  } catch (error) {
    console.error('Database connection error:', error);
    return res.status(500).json({ message: 'Unable to connect to database' });
  }
});

// API to get session details
app.get('/session', (req, res) => {
  if (req.session && req.session.userId) {
    return res.status(200).json({
      userId: req.session.userId,
      userName: req.session.userName,
    });
  } else {
    return res.status(401).json({ message: 'User not logged in' });
  }
});

app.get('/Designations', async (req, res) => {
    try {
        const data = await getDesignations();
        res.json(data);
    } catch (error) {
        res.status(500).send('Error fetching category');
    }
});

app.get('/Departments', async (req, res) => {
  try {
      const data = await getDepartment();
      res.json(data);
  } catch (error) {
      res.status(500).send('Error fetching departments');
  }
});

app.get('/leave-descriptions', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();

    // SQL query with positional bind variable
    const query = `
      SELECT LAPMAB_LEAVE_DESC
      FROM trs.LAPMAB_LEAVE_TYPES
      WHERE LAPMAB_CLOSURE_TAG = :1
    `;

    const result = await connection.execute(
      query,
      ['A'], // Positional bind parameter
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    // Detailed error logging
    console.error("Error retrieving leave descriptions:", error);

    // Handle table not found error
    if (error.errorNum === 942) {
      return res.status(404).json({ 
        success: false, 
        error: "Table 'trs.LAPMAB_LEAVE_TYPES' not found. Please verify the table name, schema, or database permissions."
      });
    }

    // Handle illegal variable name/number error
    if (error.errorNum === 1036) {
      return res.status(500).json({ 
        success: false, 
        error: "Invalid bind variable in query. Please check the query parameters."
      });
    }

    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});



app.get('/training-type', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();
    
    const query = `
      SELECT 
        QMSMAE_CATEG_NAME,
        QMSMAE_CATEG_CODE AS QMSMAA_CATEG_CODE
      FROM 
        hms.QMSMAE_CATEG_MASTER
      ORDER BY 
        QMSMAE_CATEG_NAME ASC
    `;
    
    const result = await connection.execute(
      query,
      {},
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving training types:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/training-categories/:trainingType', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();
    const trainingType = req.params.trainingType;
    
    const query = `
      SELECT 
        c.QMSMAA_DR_TR_DESCRIPTION AS CATEGORY_NAME,
        QMSMAA_DR_TR_CODE AS QMSMAE_DR_TR_CODE
      FROM 
        hms.QMSMAA_DR_TR_CATEGORY c
      JOIN 
        hms.QMSMAE_CATEG_MASTER m
      ON 
        c.QMSMAA_CATEG_CODE = m.QMSMAE_CATEG_CODE
      WHERE 
        m.QMSMAE_CATEG_NAME = :trainingType
      ORDER BY 
        c.QMSMAA_DR_TR_DESCRIPTION ASC
    `;
    
    const result = await connection.execute(
      query,
      { trainingType },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving training categories:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/training-subcategories/:trainingCategories', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();
    const trainingCategory = req.params.trainingCategories;
    
    const query = `
      SELECT 
        s.QMSMAF_DESCRIPTION,
        s.QMSMAF_SUB_CODE 
      FROM 
        hms.QMSMAF_DR_TR_SUB_CATEG s
      JOIN 
        hms.QMSMAA_DR_TR_CATEGORY c
      ON 
        s.QMSMAF_DR_TR_CODE = c.QMSMAA_DR_TR_CODE
      WHERE 
        c.QMSMAA_DR_TR_DESCRIPTION = :trainingCategory
      ORDER BY 
        s.QMSMAF_DESCRIPTION ASC
    `;
    
    const result = await connection.execute(
      query,
      { trainingCategory },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving training subcategories:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

// New endpoint to check for scheduling conflicts
app.post('/check-schedule-conflict', async (req, res) => {
  const {
    trainingDate,
    fromtime,
    totime,
    venue // Optional: you might also want to check venue conflicts
  } = req.body;
  
  let connection;
  try {
    connection = await connectDb_dev();
    
    // Format the date for Oracle comparison
    // Query to check if there's any conflict with existing schedules
    const query = `
      SELECT 
        TRAININGSESSIONNO, 
        TOPICNAME,
        TO_CHAR(TRAININGDATE, 'DD-MM-YYYY') AS FORMATTED_DATE,
        FROM_TRAINING_TIME,
        TO_TRAINING_TIME,
        VENUE
      FROM 
        trs.SCHEDULE_NABH_TRAINING
      WHERE 
        TRAININGDATE = TO_DATE(:trainingDate, 'MM-DD-YYYY')
        AND (
          -- Case 1: New training starts during an existing training
          (:fromtime >= FROM_TRAINING_TIME AND :fromtime < TO_TRAINING_TIME)
          OR
          -- Case 2: New training ends during an existing training
          (:totime > FROM_TRAINING_TIME AND :totime <= TO_TRAINING_TIME)
          OR
          -- Case 3: New training completely overlaps an existing training
          (:fromtime <= FROM_TRAINING_TIME AND :totime >= TO_TRAINING_TIME)
        )
    `;
    
    const binds = {
      trainingDate,
      fromtime,
      totime
    };
    
    const result = await connection.execute(query, binds, { 
      outFormat: oracledb.OUT_FORMAT_OBJECT 
    });
    
    // If there are any conflicts, send them back to the client
    if (result.rows && result.rows.length > 0) {
      return res.status(200).json({
        success: false,
        hasConflict: true,
        message: "This time has been scheduled in trainings",
        conflictingSchedules: result.rows
      });
    }
    
    // No conflicts found
    return res.status(200).json({
      success: true,
      hasConflict: false,
      message: "No scheduling conflicts found"
    });
    
  } catch (error) {
    console.error("Error checking schedule conflicts:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Error checking scheduling conflicts" 
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing database connection:", err);
      }
    }
  }
});

app.post('/insert-training', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();
    const {
      topicName,
      category,
      department,
      designation,
      trainees,
      trainers,
      outsideTrainers,
      trainingType,
      trainingCategory,
      trainingSubCategory,
      fromtime,
      totime,
      venue,
      trainingDate,
      participant
    } = req.body;

    // Validate required fields
    if (!topicName || !fromtime || !totime || !venue || !trainingDate || !trainingType || !participant) {
      return res.status(400).json({ success: false, error: 'All required fields must be provided' });
    }

    // Check for time conflict
    const conflictQuery = `
      SELECT COUNT(*) AS conflict_count
      FROM trs.SCHEDULE_NABH_TRAINING
      WHERE TRAININGDATE = TO_DATE(:trainingDate, 'MM-DD-YYYY')
      AND FROM_TRAINING_TIME = :fromtime
      AND TO_TRAINING_TIME = :totime
    `;
    const conflictBinds = { trainingDate, fromtime, totime };
    const conflictResult = await connection.execute(conflictQuery, conflictBinds, { outFormat: oracledb.OUT_FORMAT_OBJECT });

    const conflictCount = conflictResult.rows[0].CONFLICT_COUNT;
    if (conflictCount > 0) {
      return res.status(409).json({ 
        success: false, 
        error: 'A training session with the same date, start time, and end time already exists' 
      });
    }

    // Insert the new training record
    const insertQuery = `
      INSERT INTO trs.SCHEDULE_NABH_TRAINING (
        TOPICNAME,
        CATEGORY,
        DEPARTMENT,
        DESIGNATION,
        TRAINEES,
        TRAINERNAME,
        OUTSIDE_TRAINERS,
        TRAININGTYPE,
        TRAINING_CATEGORY,
        TRAINING_SUB_CATEGORY,
        FROM_TRAINING_TIME,
        TO_TRAINING_TIME,
        VENUE,
        TRAININGDATE,
        PARTICIPANTS
      ) VALUES (
        :topicName,
        :category,
        :department,
        :designation,
        :trainees,
        :trainers,
        :outsideTrainers,
        :trainingType,
        :trainingCategory,
        :trainingSubCategory,
        :fromtime,
        :totime,
        :venue,
        TO_DATE(:trainingDate, 'MM-DD-YYYY'),
        :participant
      )
    `;

    const binds = {
      topicName,
      category,
      department,
      designation,
      trainees,
      trainers: trainers || null,
      outsideTrainers: outsideTrainers || null,
      trainingType,
      trainingCategory,
      trainingSubCategory,
      fromtime,
      totime,
      venue,
      trainingDate,
      participant
    };

    await connection.execute(insertQuery, binds, { autoCommit: true });
    res.status(200).json({ success: true, message: 'Training scheduled successfully' });
  } catch (error) {
    console.error('Error inserting training:', error);
    res.status(500).json({ success: false, error: error.message || 'Server error' });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error('Error closing connection:', error);
      }
    }
  }
});


app.get('/training-schedules', async (req, res) => {
  let connection;
  
  try {
    connection = await connectDb_dev();
    
    // Get current date in the format required for comparison
    const currentDate = new Date();
    const formattedDate = currentDate.toISOString().split('T')[0]; // YYYY-MM-DD format
    
    // Query to get only valid training records
    const query = `
      SELECT 
        TRAININGSESSIONNO, 
        TOPICNAME, 
        CATEGORY, 
        DEPARTMENT, 
        DESIGNATION, 
        TRAINEES,
        TRAINERNAME,
        OUTSIDE_TRAINERS, 
        TRAININGTYPE, 
        FROM_TRAINING_TIME, 
        TO_TRAINING_TIME, 
        VENUE, 
        TO_CHAR(TRAININGDATE, 'DD-MM-YYYY') AS FORMATTED_DATE,
        PARTICIPANTS
      FROM 
        trs.SCHEDULE_NABH_TRAINING
      WHERE 
        TRAININGDATE >= TO_DATE(:currentDate, 'YYYY-MM-DD')
        AND TRAININGSESSIONNO IS NOT NULL  -- Ensure record exists
      ORDER BY 
        TRAININGDATE ASC, FROM_TRAINING_TIME ASC`;
    
    // Execute the query with the current date as a parameter
    const result = await connection.execute(query, { currentDate: formattedDate }, { 
      outFormat: oracledb.OUT_FORMAT_OBJECT 
    });


    console.log(result,query, { currentDate: formattedDate})
    // Check if any records were found
    if (!result.rows || result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        count: 0,
        data: []
      });
    }

    // Convert time format in JavaScript
    const trainingSchedules = result.rows.map(row => {
      // Function to convert 24-hour format to 12-hour format
      const convertTo12Hour = (time24) => {
        if (!time24 || !time24.match(/^\d{1,2}:\d{2}$/)) return time24;
        
        const [hours, minutes] = time24.split(':');
        const hour = parseInt(hours, 10);
        const period = hour >= 12 ? 'PM' : 'AM';
        const hour12 = hour % 12 || 12;
        
        return `${hour12}:${minutes} ${period}`;
      };
      console.log(row)
      return {
        ...row,
        FROM_TRAINING_TIME: convertTo12Hour(row.FROM_TRAINING_TIME),
        TO_TRAINING_TIME: convertTo12Hour(row.TO_TRAINING_TIME)
      };
    });
    
    // Send success response
    res.status(200).json({
      success: true,
      count: trainingSchedules.length,
      data: trainingSchedules
    });
    
  } catch (error) {
    console.error("Error fetching training schedules:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Error fetching training schedules" 
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing database connection:", err);
      }
    }
  }
});


// Add this new endpoint to your backend code
app.get('/training-schedules/:topicName', async (req, res) => {
  let connection;
  
  try {
    connection = await connectDb_dev();
    
    const { topicName } = req.params;
    
    // Query to get specific training record by topicName, converting CLOBs to strings
    const query = `
      SELECT 
        TRAININGSESSIONNO, 
        TOPICNAME, 
        DBMS_LOB.SUBSTR(CATEGORY, 4000, 1) AS CATEGORY, 
        DBMS_LOB.SUBSTR(DEPARTMENT, 4000, 1) AS DEPARTMENT, 
        DBMS_LOB.SUBSTR(DESIGNATION, 4000, 1) AS DESIGNATION, 
        DBMS_LOB.SUBSTR(TRAINERNAME, 4000, 1) AS TRAINERNAME, 
        DBMS_LOB.SUBSTR(TRAININGTYPE, 4000, 1) AS TRAININGTYPE, 
        FROM_TRAINING_TIME, 
        TO_TRAINING_TIME, 
        DBMS_LOB.SUBSTR(VENUE, 4000, 1) AS VENUE, 
        TO_CHAR(TRAININGDATE, 'DD-MM-YYYY') AS FORMATTED_DATE,
        PARTICIPANTS,
        DBMS_LOB.SUBSTR(TRAINEES, 4000, 1) AS TRAINEES
      FROM 
        trs.SCHEDULE_NABH_TRAINING
      WHERE 
        TOPICNAME = :topicName
    `;
    
    // Execute the query with the topicName as a parameter
    const result = await connection.execute(query, { topicName }, { 
      outFormat: oracledb.OUT_FORMAT_OBJECT 
    });
    
    // Check if any records were found
    if (!result.rows || result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Training not found"
      });
    }

    // Get the first matching record
    const trainingData = result.rows[0];
    
    // Function to convert 24-hour format to 12-hour format
    const convertTo12Hour = (time24) => {
      if (!time24 || !time24.match(/^\d{1,2}:\d{2}$/)) return time24 || '';
      
      const [hours, minutes] = time24.split(':');
      const hour = parseInt(hours, 10);
      const period = hour >= 12 ? 'PM' : 'AM';
      const hour12 = hour % 12 || 12;
      
      return `${hour12}:${minutes} ${period}`;
    };
    
    // Convert time formats and ensure all fields are strings
    const formattedData = {
      TRAININGSESSIONNO: trainingData.TRAININGSESSIONNO || '',
      TOPICNAME: trainingData.TOPICNAME || '',
      CATEGORY: trainingData.CATEGORY || '',
      DEPARTMENT: trainingData.DEPARTMENT || '',
      DESIGNATION: trainingData.DESIGNATION || '',
      TRAINERNAME: trainingData.TRAINERNAME || '',
      TRAININGTYPE: trainingData.TRAININGTYPE || '',
      FROM_TRAINING_TIME: convertTo12Hour(trainingData.FROM_TRAINING_TIME),
      TO_TRAINING_TIME: convertTo12Hour(trainingData.TO_TRAINING_TIME),
      VENUE: trainingData.VENUE || '',
      FORMATTED_DATE: trainingData.FORMATTED_DATE || '',
      PARTICIPANTS: trainingData.PARTICIPANTS ? trainingData.PARTICIPANTS.toString() : '0',
      TRAINEES: trainingData.TRAINEES || ''
    };
    
    // Send success response
    res.status(200).json({
      success: true,
      data: formattedData
    });
    
  } catch (error) {
    console.error("Error fetching training details:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Error fetching training details" 
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing database connection:", err);
      }
    }
  }
});

app.get('/training-history', async (req, res) => {
  let connection;
  
  try {
    connection = await connectDb_dev();
    
    // Get current date in the format required for comparison
    const currentDate = new Date();
    const formattedDate = currentDate.toISOString().split('T')[0]; // YYYY-MM-DD format
    
    // Query to get only past training records (less than current date)
    const query = `
      SELECT 
        TRAININGSESSIONNO, 
        TOPICNAME, 
        CATEGORY, 
        DEPARTMENT, 
        DESIGNATION, 
        TRAINEES,
        TRAINERNAME, 
        TRAININGTYPE, 
        FROM_TRAINING_TIME, 
        TO_TRAINING_TIME, 
        VENUE, 
        TO_CHAR(TRAININGDATE, 'DD-MM-YYYY') AS FORMATTED_DATE,
        PARTICIPANTS
      FROM 
        trs.SCHEDULE_NABH_TRAINING
      WHERE 
        TRAININGDATE < TO_DATE(:currentDate, 'YYYY-MM-DD')
        AND TRAININGSESSIONNO IS NOT NULL  -- Ensure record exists
      ORDER BY 
        TRAININGDATE DESC, FROM_TRAINING_TIME ASC
    `;
    
    // Execute the query with the current date as a parameter
    const result = await connection.execute(query, { currentDate: formattedDate }, { 
      outFormat: oracledb.OUT_FORMAT_OBJECT 
    });
    
    // Check if any records were found
    if (!result.rows || result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        count: 0,
        data: []
      });
    }
    
    // Convert time format in JavaScript
    const trainingHistory = result.rows.map(row => {
      // Function to convert 24-hour format to 12-hour format
      const convertTo12Hour = (time24) => {
        if (!time24 || !time24.match(/^\d{1,2}:\d{2}$/)) return time24;
        
        const [hours, minutes] = time24.split(':');
        const hour = parseInt(hours, 10);
        const period = hour >= 12 ? 'PM' : 'AM';
        const hour12 = hour % 12 || 12;
        
        return `${hour12}:${minutes} ${period}`;
      };
      
      return {
        ...row,
        FROM_TRAINING_TIME: convertTo12Hour(row.FROM_TRAINING_TIME),
        TO_TRAINING_TIME: convertTo12Hour(row.TO_TRAINING_TIME)
      };
    });
    
    // Send success response
    res.status(200).json({
      success: true,
      count: trainingHistory.length,
      data: trainingHistory
    });
    
  } catch (error) {
    console.error("Error fetching training history:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Error fetching training history" 
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing database connection:", err);
      }
    }
  }
});

app.post("/insert-feedback-training", async (req, res) => {
  const {
    trainingSessionNo,
    topicName,
    trainerName,
    trainingType,
    feedbackdate,
    category,
    department,
    designation,
    feedbacktraininglink,
  } = req.body;

  let connection;
  try {
    connection = await connectDb_dev();

    const query = `
      INSERT INTO trs.SCHEDULEFEEDBACK_NABH_TRAINING (
        TRAININGSESSIONNO, TOPICNAME, TRAINERNAME, 
        TRAININGTYPE, FEEDBACK_DATE, CATEGORY, DEPARTMENT, DESIGNATION, FEEDBACKLINK
      ) VALUES (
        :trainingSessionNo, :topicName, :trainerName, 
        :trainingType, TO_DATE(:feedbackdate, 'DD-MM-YYYY'), :category, :department, :designation, :feedbacktraininglink
      )`;

    const binds = {
      trainingSessionNo,
      topicName,
      trainerName,
      trainingType,
      feedbackdate,
      category,
      department,
      designation,
      feedbacktraininglink,
    };

    const options = { autoCommit: true };
    await connection.execute(query, binds, options);

    res.status(200).json({ message: "Training Feedback Schedule inserted successfully" });
  } catch (error) {
    console.error("Error inserting data:", error);
    res.status(500).json({ error: error.message || "Database error" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.post("/outsidetrainers", async (req, res) => {
  const {
    name,
    email,
    mobilenumber,
    dob,
    place,
    address,
    designation,
    doj,
  } = req.body;

  let connection;
  try {
    connection = await connectDb_dev();

    const query = `
      INSERT INTO trs.SCHEDULE_NABH_OUTSIDERS_TRAINING (
        NAME, EMAIL, MOBILENUMBER, 
        DOB, PLACE, ADDRESS, DESIGNATION, DOJ
      ) VALUES (
        :name, :email, :mobilenumber, 
         TO_DATE(:dob, 'DD-MM-YYYY'), :place, :address, :designation, TO_DATE(:doj, 'DD-MM-YYYY')
      )`;

    const binds = {
      name,
      email,
      mobilenumber,
      dob,
      place,
      address,
      designation,
      designation,
      doj,
    };

    const options = { autoCommit: true };
    await connection.execute(query, binds, options);

    res.status(200).json({ message: "Outsiders details inserted successfully" });
  } catch (error) {
    console.error("Error inserting data:", error);
    res.status(500).json({ error: error.message || "Database error" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.post("/scheduletrainingcategorymaster", async (req, res) => {
  const {
    categcode,
    categname,
    categcodeone,
    code,
    categorydepartment,
    categdescription,
    categduration,
    categorytrainer,
    categorytag,
    modulesubcode,
    Subcode,
    subcategdescription,
    subcategorder,
    subcategduration,
    subcategtrainer,
  } = req.body;

  // Validate required fields
  if (!categcode) {
    return res.status(400).json({ error: "CATEGORY_CODE is required" });
  }

  let connection;
  try {
    connection = await connectDb_dev();

    const query = `
      INSERT INTO hms.NABH_TRAINING_CATEGORY_MASTER (
        CATEGORY_CODE, CATEGORY_NAME, CATEGORY_CODE_ONE, CODE, CATEGORY_DEPARTMENT, 
        CATEGORY_DESCRIPTION, CATEGORY_DURATION, CATEGORY_TRAINER, CATEGORY_TAG, 
        MODULE_SUBCODE, SUB_CODE, SUB_CATEGORY_DESCRIPTION, SUB_CATEGORY_ORDER, 
        SUB_CATEGORY_DURATION, SUB_CATEGORY_TRAINER
      ) VALUES (
        :categcode, :categname, :categcodeone, :code, :categorydepartment, 
        :categdescription, :categduration, :categorytrainer, :categorytag, 
        :modulesubcode, :subcode, :subcategdescription, :subcategorder, 
        :subcategduration, :subcategtrainer
      )`;
    const binds = {
      categcode,
      categname,
      categcodeone,
      code,
      categorydepartment,
      categdescription,
      categduration,
      categorytrainer,
      categorytag,
      modulesubcode,
      subcode: Subcode, // Map Subcode to subcode for consistency
      subcategdescription,
      subcategorder,
      subcategduration,
      subcategtrainer,
    };

    const options = { autoCommit: true };
    await connection.execute(query, binds, options);

    res.status(200).json({ message: "Training inserted successfully" });
  } catch (error) {
    console.error("Error inserting data:", error, { query, binds });
    res.status(500).json({ error: error.message || "Database error" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/code/:categcodeone', async (req, res) => {
  let connection;
  try {
    const { categcodeone } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT QMSMAA_DR_TR_CODE 
      FROM hms.QMSMAA_DR_TR_CATEGORY 
      WHERE QMSMAA_CATEG_CODE = :categcodeone
    `;
    
    const result = await connection.execute(
      query,
      { categcodeone },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving trainer codes:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/categdescription/:code', async (req, res) => {
  let connection;
  try {
    const { code } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT QMSMAA_DR_TR_DESCRIPTION 
      FROM hms.QMSMAA_DR_TR_CATEGORY 
      WHERE QMSMAA_DR_TR_CODE = :code
    `;
    
    const result = await connection.execute(
      query,
      { code },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving category descriptions:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/categ-trainers', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();
    
    const query = `SELECT DISTINCT QMSMAA_TITLE_TRAINER FROM hms.QMSMAA_DR_TR_CATEGORY`;
    
    const result = await connection.execute(
      query,
      {},
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving trainers types:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/categcode', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();
    
    const query = `SELECT DISTINCT QMSMAE_CATEG_CODE 
FROM hms.QMSMAE_CATEG_MASTER
ORDER BY QMSMAE_CATEG_CODE ASC`;
    
    const result = await connection.execute(
      query,
      {},
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving trainers types:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/modulesubcategcode', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();
    
    const query = `SELECT DISTINCT QMSMAF_DR_TR_CODE
FROM hms.QMSMAF_DR_TR_SUB_CATEG`;
    
    const result = await connection.execute(
      query,
      {},
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving module sub categcode:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/subcode/:modulesubcategcode', async (req, res) => {
  let connection;
  try {
    const { modulesubcategcode } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT DISTINCT QMSMAF_SUB_CODE
      FROM hms.QMSMAF_DR_TR_SUB_CATEG
      WHERE QMSMAF_DR_TR_CODE = :modulesubcategcode
      ORDER BY QMSMAF_SUB_CODE ASC
    `;
    
    const result = await connection.execute(
      query,
      { modulesubcategcode },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    if (result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        data: [],
        message: "No subcodes found for the specified module subcode"
      });
    }
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving subcodes:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/subcategdescription/:modulesubcategcode', async (req, res) => {
  let connection;
  try {
    const { modulesubcategcode } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT DISTINCT QMSMAF_DESCRIPTION
      FROM hms.QMSMAF_DR_TR_SUB_CATEG
      WHERE QMSMAF_DR_TR_CODE = :modulesubcategcode
      ORDER BY QMSMAF_DESCRIPTION ASC
    `;
    
    const result = await connection.execute(
      query,
      { modulesubcategcode },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    if (result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        data: [],
        message: "No descriptions found for the specified module subcode"
      });
    }
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving subcategory descriptions:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

// API to fetch subcategory orders based on modulesubcategcode
app.get('/subcategorder/:modulesubcategcode', async (req, res) => {
  let connection;
  try {
    const { modulesubcategcode } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT DISTINCT QMSMAF_ORDER
      FROM hms.QMSMAF_DR_TR_SUB_CATEG
      WHERE QMSMAF_DR_TR_CODE = :modulesubcategcode
      ORDER BY QMSMAF_ORDER ASC
    `;
    
    const result = await connection.execute(
      query,
      { modulesubcategcode },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    if (result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        data: [],
        message: "No orders found for the specified module subcode"
      });
    }
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving subcategory orders:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/subduration/:modulesubcategcode', async (req, res) => {
  let connection;
  try {
    const { modulesubcategcode } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT DISTINCT QMSMAF_DURATION
      FROM hms.QMSMAF_DR_TR_SUB_CATEG
      WHERE QMSMAF_DR_TR_CODE = :modulesubcategcode
      ORDER BY QMSMAF_DURATION ASC
    `;
    
    const result = await connection.execute(
      query,
      { modulesubcategcode },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    if (result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        data: [],
        message: "No durations found for the specified module subcode"
      });
    }
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving subcategory durations:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});


app.get('/categcodeone', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();
    
    const query = `SELECT DISTINCT QMSMAA_CATEG_CODE
FROM hms.QMSMAA_DR_TR_CATEGORY ORDER BY QMSMAA_CATEG_CODE ASC`;
    
    const result = await connection.execute(
      query,
      {},
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving trainers types:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/categtrainer/:categcodeone', async (req, res) => {
  let connection;
  try {
    const { categcodeone } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT DISTINCT QMSMAA_TITLE_TRAINER
      FROM hms.QMSMAA_DR_TR_CATEGORY
      WHERE QMSMAA_CATEG_CODE = :categcodeone
      ORDER BY QMSMAA_TITLE_TRAINER ASC
    `;
    
    const result = await connection.execute(
      query,
      { categcodeone }, // Bind the categcodeone parameter
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving trainers:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/subcategtrainer/:modulesubcategcode', async (req, res) => {
  let connection;
  try {
    const { modulesubcategcode } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT DISTINCT QMSMAF_TITLE_TRAINER
      FROM hms.QMSMAF_DR_TR_SUB_CATEG
      WHERE QMSMAF_DR_TR_CODE = :modulesubcategcode
      ORDER BY QMSMAF_TITLE_TRAINER ASC
    `;
    
    const result = await connection.execute(
      query,
      { modulesubcategcode },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    if (result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        data: [],
        message: "No trainers found for the specified module subcode"
      });
    }
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving subcategory trainers:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/categdept/:categcodeone', async (req, res) => {
  let connection;
  try {
    const { categcodeone } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT DISTINCT d.EPDMBA_DEPT_LNAME
      FROM hms.QMSMAA_DR_TR_CATEGORY c
      JOIN trs.EPDMBA_DEPARTMENT d ON c.QMSMAA_DR_TR_DEPT = d.EPDMBA_DEPT_NO
      WHERE c.QMSMAA_CATEG_CODE = :categcodeone
      ORDER BY d.EPDMBA_DEPT_LNAME ASC
    `;
    
    const result = await connection.execute(
      query,
      { categcodeone },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    if (result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        data: [],
        message: "No departments found for the specified category code"
      });
    }
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving departments:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

// Duration endpoint (unchanged)
app.get('/duration/:categcodeone', async (req, res) => {
  let connection;
  try {
    const { categcodeone } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT DISTINCT QMSMAA_DURATION 
      FROM hms.QMSMAA_DR_TR_CATEGORY 
      WHERE QMSMAA_CATEG_CODE = :categcodeone
      ORDER BY QMSMAA_DURATION ASC
    `;
    
    const result = await connection.execute(
      query,
      { categcodeone },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    if (result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        data: [],
        message: "No durations found for the specified category code"
      });
    }
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving durations:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/categtag/:categcodeone', async (req, res) => {
  let connection;
  try {
    const { categcodeone } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT DISTINCT QMSMAA_DR_TR_TAG
      FROM hms.QMSMAA_DR_TR_CATEGORY
      WHERE QMSMAA_CATEG_CODE = :categcodeone
      ORDER BY QMSMAA_DR_TR_TAG ASC
    `;
    
    const result = await connection.execute(
      query,
      { categcodeone },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    if (result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        data: [],
        message: "No tags found for the specified category code"
      });
    }
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving category tags:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/categname/:categcode', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();
    const categcode = req.params.categcode;

    const query = `SELECT DISTINCT QMSMAE_CATEG_NAME
                   FROM hms.QMSMAE_CATEG_MASTER
                   WHERE QMSMAE_CATEG_CODE = :categcode`;

    const result = await connection.execute(
      query,
      { categcode },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving category names:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

app.get('/categdept/:categcode', async (req, res) => {
  let connection;
  try {
    const { categcode } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT DISTINCT QMSMAA_DR_TR_DEPT
      FROM hms.QMSMAA_DR_TR_CATEGORY
      WHERE QMSMAA_CATEG_CODE = :categcode
      ORDER BY QMSMAA_DR_TR_DEPT ASC
    `;
    
    const result = await connection.execute(
      query,
      { categcode },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    if (result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        data: [],
        message: "No departments found for the specified category code"
      });
    }
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving category departments:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

// Existing duration endpoint (from previous response)
app.get('/categdept/:categcodeone', async (req, res) => {
  let connection;
  try {
    const { categcodeone } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT DISTINCT d.EPDMBA_DEPT_LNAME
      FROM hms.QMSMAA_DR_TR_CATEGORY c
      JOIN trs.EPDMBA_DEPARTMENT d ON c.QMSMAA_DR_TR_DEPT = d.EPDMBA_DEPT_NO
      WHERE c.QMSMAA_CATEG_CODE = :categcodeone
      ORDER BY d.EPDMBA_DEPT_LNAME ASC
    `;
    
    const result = await connection.execute(
      query,
      { categcodeone },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    if (result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        data: [],
        message: "No departments found for the specified category code"
      });
    }
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving departments:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});


app.get('/subcategdescription/:modulesubcategcode', async (req, res) => {
  let connection;
  try {
    const { modulesubcategcode } = req.params;
    connection = await connectDb_dev();
    
    const query = `
      SELECT DISTINCT QMSMAF_DESCRIPTION
      FROM hms.QMSMAF_DR_TR_SUB_CATEG
      WHERE QMSMAF_DR_TR_CODE = :modulesubcategcode
      ORDER BY QMSMAF_DESCRIPTION ASC
    `;
    
    const result = await connection.execute(
      query,
      { modulesubcategcode },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    if (result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        data: [],
        message: "No descriptions found for the specified module subcode"
      });
    }
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving subcategory descriptions:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});


app.get('/outsideshowtrainers', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();
    
    const query = `
      SELECT 
        ID, NAME
      FROM 
        trs.SCHEDULE_NABH_OUTSIDERS_TRAINING
    `;
    
    const result = await connection.execute(
      query,
      {},
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error("Error retrieving trainers types:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Database error"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

// BACKEND CODE (for server.js)
app.post('/cancel-training', async (req, res) => {
  const { trainingSessionNo } = req.body;
  
  // Validate input
  if (!trainingSessionNo) {
    return res.status(400).json({
      success: false,
      error: 'Training session number is required'
    });
  }
  let connection;
  
  try {
    connection = await connectDb_dev();
    
    // Oracle doesn't need explicit beginTransaction - transactions start automatically
    
    // Optional: Log the cancellation for audit purposes (if the table exists)
    try {
      await connection.execute(
        `INSERT INTO TRS.TRAINING_CANCELLATION_LOG 
         (TRAINING_SESSION_NO, CANCELLED_BY, CANCELLED_DATE) 
         VALUES (:1, :2, SYSDATE)`,
        [trainingSessionNo, req.session?.userId || 'admin']
      );
    } catch (logErr) {
      // If the log table doesn't exist, just continue
      console.warn('Could not log cancellation:', logErr.message);
    }
    
    // Delete the training session from the database
    const result = await connection.execute(
      'DELETE FROM TRS.SCHEDULE_NABH_TRAINING WHERE TRAININGSESSIONNO = :1',
      [trainingSessionNo]
    );
    
    // Commit the transaction
    await connection.commit();
    
    // Check if any rows were affected
    if (result.rowsAffected === 0) {
      return res.status(404).json({
        success: false,
        error: 'Training session not found'
      });
    }
    
    // Return success response
    return res.status(200).json({
      success: true,
      message: 'Training successfully cancelled',
      data: { trainingSessionNo }
    });
    
  } catch (error) {
    // Rollback transaction in case of error
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackErr) {
        console.error('Error during rollback:', rollbackErr);
      }
    }
    
    console.error('Error cancelling training:', error);
    
    return res.status(500).json({
      success: false,
      error: 'Failed to cancel training. Please try again later.',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
    
  } finally {
    // Close the connection (not release with oracledb)
    if (connection) {
      try {
        await connection.close();
      } catch (closeErr) {
        console.error('Error closing connection:', closeErr);
      }
    }
  }
});

app.get('/get-all-feedback-training', async (req, res) => {
  let connection;
  
  try {
    connection = await connectDb_dev();
    
    // Query to fetch past training records where FEEDBACK_DATE is before today
    const query = `
      SELECT 
        TRAININGSESSIONNO, 
        TOPICNAME, 
        TRAINERNAME, 
        TRAININGTYPE, 
        CATEGORY, 
        DEPARTMENT, 
        DESIGNATION, 
        TO_CHAR(FEEDBACK_DATE, 'DD-MM-YYYY') AS FORMATTED_DATE,
        FEEDBACKLINK
      FROM 
        trs.SCHEDULEFEEDBACK_NABH_TRAINING`; // Fetch only past training feedback

    // Execute query (No bind variables needed)
    const result = await connection.execute(query, [], { 
      outFormat: oracledb.OUT_FORMAT_OBJECT 
    });
    
    // Check if any records were found
    if (!result.rows || result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        count: 0,
        data: []
      });
    }
    
    // Send success response
    res.status(200).json({ 
      success: true, 
      count: result.rows.length,
      data: result.rows 
    });
    
  } catch (error) {
    console.error("Error fetching training history:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Error fetching training history" 
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing database connection:", err);
      }
    }
  }
});

app.post('/apply-leave', upload.single('medicalCertificate'), async (req, res) => {
  let connection;
  logger.info('Received /apply-leave request', { body: req.body, file: req.file });
  try {
    const {
      name,
      employeeId,
      leaveType,
      department,
      fromDate,
      toDate,
      reason,
      sessionFrom,
      sessionTo,
      userId,
      hoursWorked,
      replacementEmployeeId,
    } = req.body;

    const medicalCertificatePath = req.file ? req.file.path : null;
    logger.info('Parsed request body', { employeeId, leaveType, fromDate, userId, medicalCertificatePath });

    // Validate required fields and their format
    if (!employeeId || !leaveType || !fromDate || !userId) {
      logger.warn('Missing required fields', { employeeId, leaveType, fromDate, userId });
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: employeeId, leaveType, fromDate, userId',
      });
    }

    if (!/^\d+$/.test(employeeId) || !/^\d+$/.test(userId)) {
      logger.warn('Invalid employeeId or userId format', { employeeId, userId });
      return res.status(400).json({
        success: false,
        message: 'employeeId and userId must be numeric',
      });
    }

    const leaveTypeMap = {
      'CASUAL': 'CL',
      'EARNED': 'EL',
      'MEDICAL': 'ML',
      'SICK': 'SL',
      'ON-DUTY': 'OD',
      'COMPENSATORY': 'CO',
      'OVERTIME': 'EX',
      'CL': 'CL',
      'EL': 'EL',
      'ML': 'ML',
      'SL': 'SL',
      'OD': 'OD',
      'CO': 'CO',
      'EX': 'EX',
    };

    logger.info('Received leaveType from frontend', { leaveType, mappedLeaveType: leaveTypeMap[leaveType.toUpperCase()] });
    const leaveTypeCode = leaveTypeMap[leaveType.toUpperCase()];
    if (!leaveTypeCode) {
      logger.warn('Invalid leave type', { leaveType });
      return res.status(400).json({
        success: false,
        message: `Invalid leave type: ${leaveType}. Valid types: ${Object.keys(leaveTypeMap).join(', ')}`,
      });
    }

    // Validate document upload for ML and OD
    if (['ML', 'OD'].includes(leaveTypeCode)) {
      if (!medicalCertificatePath) {
        logger.warn('Missing document for ML/OD leave', { leaveTypeCode });
        return res.status(400).json({
          success: false,
          message: `A document (PDF, JPEG, PNG, DOC, or DOCX) is required for ${leaveTypeCode} leave type`,
        });
      }
      const allowedMimeTypes = [
        'application/pdf',
        'image/jpeg',
        'image/png',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      ];
      if (!allowedMimeTypes.includes(req.file.mimetype)) {
        logger.warn('Invalid file type', { mimetype: req.file.mimetype });
        return res.status(400).json({
          success: false,
          message: 'Invalid file type. Only PDF, JPEG, PNG, DOC, and DOCX files are allowed',
        });
      }
    }

    // Validate and map sessions
    const sessionMap = {
      'F': 'F',
      'A': 'A',
      'FORENOON': 'F',
      'AFTERNOON': 'A',
    };
    if (!sessionFrom || !sessionMap[sessionFrom.toUpperCase()]) {
      logger.warn('Invalid sessionFrom', { sessionFrom });
      return res.status(400).json({
        success: false,
        message: 'Invalid sessionFrom. Must be "F" (Forenoon) or "A" (Afternoon)',
      });
    }
    if (!sessionTo || !sessionMap[sessionTo.toUpperCase()]) {
      logger.warn('Invalid sessionTo', { sessionTo });
      return res.status(400).json({
        success: false,
        message: 'Invalid sessionTo. Must be "F" (Forenoon) or "A" (Afternoon)',
      });
    }
    const fSession = sessionMap[sessionFrom.toUpperCase()];
    const tSession = sessionMap[sessionTo.toUpperCase()];
    if (fSession === 'A' && tSession === 'F') {
      logger.warn('Invalid session range', { fSession, tSession });
      return res.status(400).json({
        success: false,
        message: 'Invalid session range: sessionFrom (A) cannot be after sessionTo (F)',
      });
    }

    // Format dates
    const formatDate = (dateStr) => {
      const date = new Date(dateStr);
      if (isNaN(date.getTime())) return null;
      return date.toISOString().split('T')[0]; // YYYY-MM-DD
    };
    const effectiveFromDate = formatDate(fromDate);
    const effectiveToDate = formatDate(toDate || fromDate);
    logger.info('Formatted dates', { effectiveFromDate, effectiveToDate });

    if (!effectiveFromDate) {
      logger.warn('Invalid fromDate format', { fromDate });
      return res.status(400).json({
        success: false,
        message: 'Invalid fromDate format. Use YYYY-MM-DD',
      });
    }
    if (!effectiveToDate) {
      logger.warn('Invalid toDate format', { toDate });
      return res.status(400).json({
        success: false,
        message: 'Invalid toDate format. Use YYYY-MM-DD',
      });
    }
    const fromDateObj = new Date(effectiveFromDate);
    const toDateObj = new Date(effectiveToDate);
    if (fromDateObj > toDateObj) {
      logger.warn('fromDate later than toDate', { fromDate, toDate });
      return res.status(400).json({
        success: false,
        message: 'fromDate cannot be later than toDate',
      });
    }

    // Calculate total days
    let totalDays = (toDateObj - fromDateObj) / (1000 * 60 * 60 * 24) + 1;
    if (fromDate === toDate) {
      if (fSession === tSession) totalDays = 0.5;
      else totalDays = 1;
    } else {
      if (fSession === 'A') totalDays -= 0.5;
      if (tSession === 'F') totalDays -= 0.5;
    }
    totalDays = Math.max(totalDays, 0);
    logger.info('Calculated total days', { totalDays });

    // Validate and adjust totalDays for EX and CO
    if (['EX', 'CO'].includes(leaveTypeCode)) {
      if (!hoursWorked) {
        logger.warn('Missing hoursWorked for EX/CO leave', { leaveTypeCode });
        return res.status(400).json({
          success: false,
          message: 'hoursWorked is required for EX/CO leave types',
        });
      }
      const hours = parseFloat(hoursWorked);
      if (isNaN(hours)) {
        logger.warn('Invalid hoursWorked format', { hoursWorked });
        return res.status(400).json({
          success: false,
          message: 'hoursWorked must be a valid number',
        });
      }
      // Set minimum hours requirement
      const minHours = leaveTypeCode === 'EX' ? 8 : 10; // EX: 8 hours, CO: 10 hours
      if (hours < minHours) {
        logger.warn('Insufficient hours worked', { leaveTypeCode, hours, required: minHours });
        return res.status(400).json({
          success: false,
          message: `Insufficient hours worked for ${leaveTypeCode} leave. Required: ${minHours} hours, Provided: ${hours} hours`,
        });
      }
      totalDays = hours >= minHours && hours < minHours + 4 ? 1 : totalDays; // Adjust based on hours
      logger.info(`Adjusted totalDays for ${leaveTypeCode}`, { hoursWorked, totalDays });
    }

    const replacementAdmNo = leaveTypeCode === 'EX' && replacementEmployeeId ? replacementEmployeeId : -1;
    if (replacementAdmNo !== -1 && !/^\d+$/.test(replacementAdmNo)) {
      logger.warn('Invalid replacementEmployeeId format', { replacementEmployeeId });
      return res.status(400).json({
        success: false,
        message: 'replacementEmployeeId must be numeric',
      });
    }

    const bindVars = {
      adm_no: employeeId,
      f_date: effectiveFromDate,
      t_date: effectiveToDate,
      f_session: fSession,
      t_session: tSession,
      leave_type: leaveTypeCode,
      replacement_adm_no: replacementAdmNo,
      remarks: reason?.slice(0, 500).trim() || 'No remarks',
      machine: 'WEB_APP'.slice(0, 20),
      total_day: totalDays,
    };
    logger.info('Prepared bind variables', { bindVars });

    connection = await connectDb_dev();
    logger.info('Connected to database');

    await connection.execute(`ALTER SESSION SET TIME_ZONE = 'UTC'`);
    logger.info('Set session timezone to UTC');

    // Check for overlaps
    const duplicateCheck = await connection.execute(
      `SELECT lapmaa_trans_id,
              lapmaa_leave_type,
              TO_CHAR(lapmaa_f_date, 'YYYY-MM-DD') AS f_date,
              TO_CHAR(lapmaa_t_date, 'YYYY-MM-DD') AS t_date,
              lapmaa_from_session,
              lapmaa_to_session,
              lapmaa_leave_status
       FROM trs.lapmaa_request_master
       WHERE lapmaa_adm_no = :adm_no
       AND lapmaa_leave_status != 'C'
       AND (
         (TO_DATE(:f_date, 'YYYY-MM-DD') <= lapmaa_t_date AND TO_DATE(:t_date, 'YYYY-MM-DD') >= lapmaa_f_date)
         AND (
           (:f_session = lapmaa_from_session OR :f_session = lapmaa_to_session OR
            :t_session = lapmaa_from_session OR :t_session = lapmaa_to_session)
           OR (:f_session = 'F' AND :t_session = 'A')
           OR (lapmaa_from_session = 'F' AND lapmaa_to_session = 'A')
         )
       )
       FOR UPDATE NOWAIT`,
      {
        adm_no: bindVars.adm_no,
        f_date: bindVars.f_date,
        t_date: bindVars.t_date,
        f_session: bindVars.f_session,
        t_session: bindVars.t_session,
      }
    );
    logger.info('Checked for duplicate leave requests', { rows: duplicateCheck.rows });

    if (duplicateCheck.rows.length > 0) {
      const conflicts = duplicateCheck.rows.map(row => ({
        transactionId: row[0],
        leaveType: row[1],
        fromDate: row[2],
        toDate: row[3],
        fromSession: row[4] === 'F' ? 'Forenoon' : 'Afternoon',
        toSession: row[5] === 'F' ? 'Forenoon' : 'Afternoon',
        status: row[6] === 'A' ? 'Approved' : row[6] === 'P' ? 'Pending' : 'Unknown',
      }));
      logger.warn('Found overlapping leave applications', { conflicts });
      return res.status(400).json({
        success: false,
        message: `Overlapping leave application(s) found for ${effectiveFromDate} to ${effectiveToDate} (${fSession}-${tSession}).`,
        conflicts: conflicts,
      });
    }

    // Check leave balance for CL, ML, EL, SL, OD
    if (['CL', 'ML', 'EL', 'SL', 'OD'].includes(leaveTypeCode)) {
      const leaveYear = new Date(effectiveFromDate).getFullYear().toString();
      let balanceResult = await connection.execute(
        `SELECT NVL(TRSTBC_ELIGIBLE_${leaveTypeCode}, 0) AS ELIG, NVL(TRSTBC_AVAILED_${leaveTypeCode}, 0) AS AVAIL
         FROM trs.TRSTBC_ELIGIBLE_LEAVE
         WHERE TRSTBC_ADM_NO = :adm_no
         AND TRSTBC_YEAR = :year`,
        {
          adm_no: bindVars.adm_no,
          year: leaveYear,
        }
      );
      logger.info('Checked leave balance', { balanceResult: balanceResult.rows });

      if (!balanceResult.rows || balanceResult.rows.length === 0) {
        logger.warn('No leave balance record found, attempting to sync leave matrix', { adm_no: bindVars.adm_no, year: leaveYear });
        try {
          const apiUrl = `http://192.168.90.106:3012/api/hr/leavematrix?admno=${bindVars.adm_no}`;
          const response = await axios.get(apiUrl);
          const leaveData = response.data[0];

          if (!leaveData) {
            logger.warn('No leave matrix data found from API', { adm_no: bindVars.adm_no });
            return res.status(400).json({
              success: false,
              message: 'No leave matrix data found for the employee. Please contact HR.',
            });
          }

          const leaveTypes = [
            { type: 'CL', eligible: leaveData.ELIGIBLE_CL || 0, availed: leaveData.AVAILED_CL || 0 },
            { type: 'EL', eligible: leaveData.ELIGIBLE_EL || 0, availed: leaveData.AVAILED_EL || 0 },
            { type: 'ML', eligible: leaveData.ELIGIBLE_ML || 0, availed: leaveData.AVAILED_ML || 0 },
            { type: 'SL', eligible: leaveData.ELIGIBLE_SL || 0, availed: leaveData.AVAILED_SL || 0 },
            { type: 'CO', eligible: leaveData.ELIGIBLE_CO || 0, availed: leaveData.AVAILED_CO || 0 },
            { type: 'EX', eligible: leaveData.ELIGIBLE_EX || 0, availed: leaveData.AVAILED_EX || 0 },
          ];

          const insertQuery = `
            MERGE INTO trs.TRSTBC_ELIGIBLE_LEAVE dest
            USING (SELECT :admno AS TRSTBC_ADM_NO, :year AS TRSTBC_YEAR,
                          :eligible_cl AS TRSTBC_ELIGIBLE_CL, :availed_cl AS TRSTBC_AVAILED_CL,
                          :eligible_el AS TRSTBC_ELIGIBLE_EL, :availed_el AS TRSTBC_AVAILED_EL,
                          :eligible_ml AS TRSTBC_ELIGIBLE_ML, :availed_ml AS TRSTBC_AVAILED_ML,
                          :eligible_sl AS TRSTBC_ELIGIBLE_SL, :availed_sl AS TRSTBC_AVAILED_SL,
                          :eligible_co AS TRSTBC_ELIGIBLE_CO, :availed_co AS TRSTBC_AVAILED_CO,
                          :eligible_ex AS TRSTBC_ELIGIBLE_EX, :availed_ex AS TRSTBC_AVAILED_EX
                   FROM DUAL) src
            ON (dest.TRSTBC_ADM_NO = src.TRSTBC_ADM_NO AND dest.TRSTBC_YEAR = src.TRSTBC_YEAR)
            WHEN MATCHED THEN
              UPDATE SET
                dest.TRSTBC_ELIGIBLE_CL = src.TRSTBC_ELIGIBLE_CL,
                dest.TRSTBC_AVAILED_CL = src.TRSTBC_AVAILED_CL,
                dest.TRSTBC_ELIGIBLE_EL = src.TRSTBC_ELIGIBLE_EL,
                dest.TRSTBC_AVAILED_EL = src.TRSTBC_AVAILED_EL,
                dest.TRSTBC_ELIGIBLE_ML = src.TRSTBC_ELIGIBLE_ML,
                dest.TRSTBC_AVAILED_ML = src.TRSTBC_AVAILED_ML,
                dest.TRSTBC_ELIGIBLE_SL = src.TRSTBC_ELIGIBLE_SL,
                dest.TRSTBC_AVAILED_SL = src.TRSTBC_AVAILED_SL,
                dest.TRSTBC_ELIGIBLE_CO = src.TRSTBC_ELIGIBLE_CO,
                dest.TRSTBC_AVAILED_CO = src.TRSTBC_AVAILED_CO,
                dest.TRSTBC_ELIGIBLE_EX = src.TRSTBC_ELIGIBLE_EX,
                dest.TRSTBC_AVAILED_EX = src.TRSTBC_AVAILED_EX
            WHEN NOT MATCHED THEN
              INSERT (TRSTBC_ADM_NO, TRSTBC_YEAR, TRSTBC_ELIGIBLE_CL, TRSTBC_AVAILED_CL,
                      TRSTBC_ELIGIBLE_EL, TRSTBC_AVAILED_EL, TRSTBC_ELIGIBLE_ML, TRSTBC_AVAILED_ML,
                      TRSTBC_ELIGIBLE_SL, TRSTBC_AVAILED_SL, TRSTBC_ELIGIBLE_CO, TRSTBC_AVAILED_CO,
                      TRSTBC_ELIGIBLE_EX, TRSTBC_AVAILED_EX)
              VALUES (src.TRSTBC_ADM_NO, src.TRSTBC_YEAR, src.TRSTBC_ELIGIBLE_CL, src.TRSTBC_AVAILED_CL,
                      src.TRSTBC_ELIGIBLE_EL, src.TRSTBC_AVAILED_EL, src.TRSTBC_ELIGIBLE_ML, src.TRSTBC_AVAILED_ML,
                      src.TRSTBC_ELIGIBLE_SL, src.TRSTBC_AVAILED_SL, src.TRSTBC_ELIGIBLE_CO, src.TRSTBC_AVAILED_CO,
                      src.TRSTBC_ELIGIBLE_EX, src.TRSTBC_AVAILED_EX)
          `;

          const bindArray = [{
            admno: bindVars.adm_no,
            year: leaveYear,
            eligible_cl: leaveTypes.find(lt => lt.type === 'CL').eligible,
            availed_cl: leaveTypes.find(lt => lt.type === 'CL').availed,
            eligible_el: leaveTypes.find(lt => lt.type === 'EL').eligible,
            availed_el: leaveTypes.find(lt => lt.type === 'EL').availed,
            eligible_ml: leaveTypes.find(lt => lt.type === 'ML').eligible,
            availed_ml: leaveTypes.find(lt => lt.type === 'ML').availed,
            eligible_sl: leaveTypes.find(lt => lt.type === 'SL').eligible,
            availed_sl: leaveTypes.find(lt => lt.type === 'SL').availed,
            eligible_co: leaveTypes.find(lt => lt.type === 'CO').eligible,
            availed_co: leaveTypes.find(lt => lt.type === 'CO').availed,
            eligible_ex: leaveTypes.find(lt => lt.type === 'EX').eligible,
            availed_ex: leaveTypes.find(lt => lt.type === 'EX').availed,
          }];

          await connection.executeMany(insertQuery, bindArray, { autoCommit: true });
          logger.info('Synced leave matrix data', { adm_no: bindVars.adm_no, year: leaveYear });

          balanceResult = await connection.execute(
            `SELECT NVL(TRSTBC_ELIGIBLE_${leaveTypeCode}, 0) AS ELIG, NVL(TRSTBC_AVAILED_${leaveTypeCode}, 0) AS AVAIL
             FROM trs.TRSTBC_ELIGIBLE_LEAVE
             WHERE TRSTBC_ADM_NO = :adm_no
             AND TRSTBC_YEAR = :year`,
            {
              adm_no: bindVars.adm_no,
              year: leaveYear,
            }
          );
          logger.info('Re-checked leave balance after sync', { balanceResult: balanceResult.rows });
        } catch (syncError) {
          logger.error('Failed to sync leave matrix data', { error: syncError.message, stack: syncError.stack });
          return res.status(400).json({
            success: false,
            message: 'Failed to sync leave balance data for the specified year. Please contact HR.',
          });
        }
      }

      if (!balanceResult.rows || balanceResult.rows.length === 0) {
        logger.warn('No leave balance record found after sync', { adm_no: bindVars.adm_no, year: leaveYear });
        return res.status(400).json({
          success: false,
          message: 'No leave balance record found for the employee in the specified year after syncing. Please contact HR.',
        });
      }

      const balance = balanceResult.rows[0];
      if (balance[0] - balance[1] < totalDays) {
        logger.warn('Insufficient leave balance', { leaveTypeCode, available: balance[0] - balance[1], requested: totalDays });
        return res.status(400).json({
          success: false,
          message: `Insufficient ${leaveTypeCode} balance. Available: ${balance[0] - balance[1]}, Requested: ${totalDays}`,
        });
      }
    }

    try {
      await connection.execute(
        `BEGIN
          trs.LEAVE_APPLICATION.apply_leave(
            :adm_no, TO_DATE(:f_date, 'YYYY-MM-DD'), TO_DATE(:t_date, 'YYYY-MM-DD'),
            :f_session, :t_session, :leave_type, :replacement_adm_no, :remarks, :machine, :total_day
          );
          COMMIT;
        END;`,
        bindVars,
        { autoCommit: true }
      );
      logger.info('Executed apply_leave procedure successfully');
    } catch (procError) {
      logger.error('Error in apply_leave procedure', { error: procError.message, stack: procError.stack });
      throw new Error(`apply_leave procedure failed: ${procError.message}`);
    }

    const transIdResult = await connection.execute(
      `SELECT lapmaa_trans_id
       FROM trs.lapmaa_request_master
       WHERE lapmaa_adm_no = :adm_no
       AND lapmaa_applied_date >= SYSDATE - 1
       AND lapmaa_leave_status IN ('P', 'A')
       AND lapmaa_leave_type = :leave_type
       AND lapmaa_f_date = TO_DATE(:f_date, 'YYYY-MM-DD')
       AND ROWNUM = 1
       ORDER BY lapmaa_applied_date DESC`,
      {
        adm_no: bindVars.adm_no,
        leave_type: bindVars.leave_type,
        f_date: bindVars.f_date,
      }
    );
    logger.info('Retrieved transaction ID', { transIdResult: transIdResult.rows });

    const formattedTransId = transIdResult.rows[0]?.[0];
    if (!formattedTransId) {
      logger.error('Failed to retrieve transaction ID');
      throw new Error('Failed to retrieve transaction ID. Please check if the leave was applied correctly.');
    }

    let documentStored = true;
    if (['ML', 'OD'].includes(leaveTypeCode) && medicalCertificatePath) {
      logger.info('Attempting to store document in TRSEPS_OD_DOC', { leaveTypeCode, transId: formattedTransId });
      try {
        const fileBuffer = await fsPromises.readFile(medicalCertificatePath);
        logger.info('File read successfully', { path: medicalCertificatePath, size: fileBuffer.length });

        const insertResult = await connection.execute(
          `INSERT INTO trs.TRSEPS_OD_DOC (
            TRSEPS_ADM_NO, TRSEPS_TRANS_ID, TRSEPS_OD, TRSEPS_OD_TYPE,
            TRSEPS_ENTRY_BY, TRSEPS_ENTRY_ON, TRSEPS_MODIFY_BY, TRSEPS_MODIFY_ON
          ) VALUES (
            :adm_no, :trans_id, :od_blob, :od_type, :entry_by, SYSDATE, :modify_by, SYSDATE
          )`,
          {
            adm_no: Number(employeeId),
            trans_id: formattedTransId,
            od_blob: { val: fileBuffer, type: oracledb.BLOB },
            od_type: req.file.mimetype,
            entry_by: Number(userId),
            modify_by: Number(userId),
          },
          { autoCommit: true }
        );
        logger.info('Document insert result', { rowsAffected: insertResult.rowsAffected });
        if (insertResult.rowsAffected !== 1) {
          logger.error('Document insert failed: No rows affected');
          throw new Error('Failed to insert document into TRSEPS_OD_DOC: No rows affected');
        }
        logger.info('Stored document in TRSEPS_OD_DOC', { leaveTypeCode, transId: formattedTransId });
      } catch (fileError) {
        logger.error('Failed to store document in TRSEPS_OD_DOC', { error: fileError.message, stack: fileError.stack });
        documentStored = false;
      }
    }

    const approvalCheck = await connection.execute(
      `SELECT lapmaa_leave_status
       FROM trs.lapmaa_request_master
       WHERE lapmaa_trans_id = :trans_id`,
      { trans_id: formattedTransId }
    );
    const isApproved = approvalCheck.rows[0]?.[0] === 'A';
    logger.info('Checked approval status', { transId: formattedTransId, isApproved });

    // Notify admin for EX/CO leave
    if (['EX', 'CO'].includes(leaveTypeCode)) {
      try {
        await axios.post('http://localhost:your-port/notify-admin', {
          userId: employeeId,
          type: leaveTypeCode === 'EX' ? 'extrawork' : 'overtime',
        });
        logger.info(`Notified admin about ${leaveTypeCode === 'EX' ? 'extrawork' : 'overtime'} application`, { employeeId });
      } catch (notifyError) {
        logger.error('Failed to notify admin', { error: notifyError.message });
        // Continue execution even if notification fails
      }
    }

    res.status(201).json({
      success: true,
      message: `${leaveTypeCode} leave application submitted successfully`,
      transId: formattedTransId,
      approved: isApproved,
      documentWarning: !documentStored ? 'Leave application submitted, but failed to store the document. Please upload the document again if needed.' : undefined,
    });
    logger.info('Leave application submitted successfully', { transId: formattedTransId, documentStored });
  } catch (error) {
    logger.error('Error submitting leave application', { error: error.message, stack: error.stack });
    if (req.file && req.file.path) {
      try {
        logger.info('Cleaning up uploaded file', { path: req.file.path });
        await fsPromises.unlink(req.file.path);
        logger.info('Cleaned up uploaded file', { path: req.file.path });
      } catch (unlinkErr) {
        logger.error('Error cleaning up uploaded file', { error: unlinkErr.message, path: req.file.path });
      }
    }
    if (error.message.includes('apply_leave procedure failed')) {
      if (error.message.includes('ORA-20001')) {
        const specificError = error.message.match(/ORA-20001: (.+?)(ORA-|$)/)?.[1] || 'Failed to apply leave due to eligibility or limit issues.';
        return res.status(400).json({ success: false, message: specificError });
      } else if (error.message.includes('ORA-20002')) {
        return res.status(400).json({ success: false, message: 'Overlapping leave application found.' });
      }
      return res.status(400).json({ success: false, message: `Failed to apply leave: ${error.message}` });
    }
    if (error.message.includes('ORA-00054')) {
      return res.status(429).json({
        success: false,
        message: 'Another leave application is being processed for this employee. Please try again later.',
      });
    }
    res.status(500).json({
      success: false,
      message: `Failed to submit leave application: ${error.message}`,
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
        logger.info('Database connection closed');
      } catch (closeError) {
        logger.error('Error closing connection', { error: closeError.message });
      }
    }
  }
});

// Leave Matrix API Endpoint
app.get('/leave-matrix/:admno', async (req, res) => {
  let connection;
  const { admno } = req.params;

  try {
    // Fetch leave matrix data from the external API
    const apiUrl = `http://192.168.90.106:3012/api/hr/leavematrix?admno=${admno}`;
    const response = await axios.get(apiUrl);
    const leaveData = response.data[0];

    if (!leaveData) {
      logger.warn('No leave matrix data found', { admno });
      return res.status(404).json({ success: false, message: 'No leave matrix data found' });
    }

    const leaveTypes = [
      { type: 'CL', eligible: leaveData.ELIGIBLE_CL || 0, availed: leaveData.AVAILED_CL || 0, balance: leaveData.BALANCE_CL || 0 },
      { type: 'EL', eligible: leaveData.ELIGIBLE_EL || 0, availed: leaveData.AVAILED_EL || 0, balance: leaveData.BALANCE_EL || 0 },
      { type: 'ML', eligible: leaveData.ELIGIBLE_ML || 0, availed: leaveData.AVAILED_ML || 0, balance: leaveData.BALANCE_ML || 0 },
      { type: 'EX', eligible: leaveData.ELIGIBLE_EX || 0, availed: leaveData.AVAILED_EX || 0, balance: leaveData.BALANCE_EX || 0 },
      { type: 'SL', eligible: leaveData.ELIGIBLE_SL || 0, availed: leaveData.AVAILED_SL || 0, balance: leaveData.BALANCE_SL || 0 },
      { type: 'CO', eligible: leaveData.ELIGIBLE_CO || 0, availed: leaveData.AVAILED_CO || 0, balance: leaveData.BALANCE_CO || 0 },
    ];

    // Initialize database connection
    connection = await connectDb_dev();
    logger.info('Connected to database for leave matrix sync', { admno });

    const insertQuery = `
      MERGE INTO trs.TRSTBC_ELIGIBLE_LEAVE dest
      USING (SELECT :admno AS TRSTBC_ADM_NO, '2025' AS TRSTBC_YEAR,
                    :eligible_cl AS TRSTBC_ELIGIBLE_CL, :availed_cl AS TRSTBC_AVAILED_CL,
                    :eligible_el AS TRSTBC_ELIGIBLE_EL, :availed_el AS TRSTBC_AVAILED_EL,
                    :eligible_ml AS TRSTBC_ELIGIBLE_ML, :availed_ml AS TRSTBC_AVAILED_ML,
                    :eligible_sl AS TRSTBC_ELIGIBLE_SL, :availed_sl AS TRSTBC_AVAILED_SL,
                    :eligible_co AS TRSTBC_ELIGIBLE_CO, :availed_co AS TRSTBC_AVAILED_CO,
                    :eligible_ex AS TRSTBC_ELIGIBLE_EX, :availed_ex AS TRSTBC_AVAILED_EX,
                   
             FROM DUAL) src
      ON (dest.TRSTBC_ADM_NO = src.TRSTBC_ADM_NO AND dest.TRSTBC_YEAR = src.TRSTBC_YEAR)
      WHEN MATCHED THEN
        UPDATE SET
          dest.TRSTBC_ELIGIBLE_CL = src.TRSTBC_ELIGIBLE_CL,
          dest.TRSTBC_AVAILED_CL = src.TRSTBC_AVAILED_CL,
          dest.TRSTBC_ELIGIBLE_EL = src.TRSTBC_ELIGIBLE_EL,
          dest.TRSTBC_AVAILED_EL = src.TRSTBC_AVAILED_EL,
          dest.TRSTBC_ELIGIBLE_ML = src.TRSTBC_ELIGIBLE_ML,
          dest.TRSTBC_AVAILED_ML = src.TRSTBC_AVAILED_ML,
          dest.TRSTBC_ELIGIBLE_SL = src.TRSTBC_ELIGIBLE_SL,
          dest.TRSTBC_AVAILED_SL = src.TRSTBC_AVAILED_SL,
          dest.TRSTBC_ELIGIBLE_CO = src.TRSTBC_ELIGIBLE_CO,
          dest.TRSTBC_AVAILED_CO = src.TRSTBC_AVAILED_CO,
          dest.TRSTBC_ELIGIBLE_EX = src.TRSTBC_ELIGIBLE_EX,
          dest.TRSTBC_AVAILED_EX = src.TRSTBC_AVAILED_EX,
          dest.TRSTBC_ELIGIBLE_OD = src.TRSTBC_ELIGIBLE_OD,
          dest.TRSTBC_AVAILED_OD = src.TRSTBC_AVAILED_OD
      WHEN NOT MATCHED THEN
        INSERT (TRSTBC_ADM_NO, TRSTBC_YEAR, TRSTBC_ELIGIBLE_CL, TRSTBC_AVAILED_CL,
                TRSTBC_ELIGIBLE_EL, TRSTBC_AVAILED_EL, TRSTBC_ELIGIBLE_ML, TRSTBC_AVAILED_ML,
                TRSTBC_ELIGIBLE_SL, TRSTBC_AVAILED_SL, TRSTBC_ELIGIBLE_CO, TRSTBC_AVAILED_CO,
                TRSTBC_ELIGIBLE_EX, TRSTBC_AVAILED_EX, TRSTBC_ELIGIBLE_OD, TRSTBC_AVAILED_OD)
        VALUES (src.TRSTBC_ADM_NO, src.TRSTBC_YEAR, src.TRSTBC_ELIGIBLE_CL, src.TRSTBC_AVAILED_CL,
                src.TRSTBC_ELIGIBLE_EL, src.TRSTBC_AVAILED_EL, src.TRSTBC_ELIGIBLE_ML, src.TRSTBC_AVAILED_ML,
                src.TRSTBC_ELIGIBLE_SL, src.TRSTBC_AVAILED_SL, src.TRSTBC_ELIGIBLE_CO, src.TRSTBC_AVAILED_CO,
    `;

    const bindArray = [{
      admno,
      eligible_cl: leaveTypes.find(lt => lt.type === 'CL').eligible,
      availed_cl: leaveTypes.find(lt => lt.type === 'CL').availed,
      eligible_el: leaveTypes.find(lt => lt.type === 'EL').eligible,
      availed_el: leaveTypes.find(lt => lt.type === 'EL').availed,
      eligible_ml: leaveTypes.find(lt => lt.type === 'ML').eligible,
      availed_ml: leaveTypes.find(lt => lt.type === 'ML').availed,
      eligible_sl: leaveTypes.find(lt => lt.type === 'SL').eligible,
      availed_sl: leaveTypes.find(lt => lt.type === 'SL').availed,
      eligible_co: leaveTypes.find(lt => lt.type === 'CO').eligible,
      availed_co: leaveTypes.find(lt => lt.type === 'CO').availed,
      eligible_ex: leaveTypes.find(lt => lt.type === 'EX').eligible,
      availed_ex: leaveTypes.find(lt => lt.type === 'EX').availed,
    }];

    await connection.executeMany(insertQuery, bindArray, { autoCommit: true });
    logger.info(`Synced leave matrix data for ADMNO ${admno} to TRSTBC_ELIGIBLE_LEAVE`);

    res.status(200).json({
      success: true,
      message: `Leave matrix data for ADMNO ${admno} synced successfully`,
      data: leaveTypes,
    });
  } catch (error) {
    logger.error('Error processing leave matrix', { error: error.message, stack: error.stack });
    res.status(500).json({
      success: false,
      message: 'Failed to sync leave matrix data',
      error: error.message,
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
        logger.info('Database connection closed');
      } catch (err) {
        logger.error('Error closing database connection', { error: err.message });
      }
    }
  }
});

// Fetch leave balance
app.get('/leave-balance/:admno', async (req, res) => {
  let connection;
  const { admno } = req.params;

  try {
    connection = await connectDb_dev();
    logger.info('Connected to database for leave balance', { admno });

    // Simplified query to avoid formatting issues
    const query = `SELECT TRSTBC_ELIGIBLE_CL AS ELIGIBLE_CL, TRSTBC_AVAILED_CL AS AVAILED_CL, NVL(TRSTBC_ELIGIBLE_CL, 0) - NVL(TRSTBC_AVAILED_CL, 0) AS BALANCE_CL, TRSTBC_ELIGIBLE_EL AS ELIGIBLE_EL, TRSTBC_AVAILED_EL AS AVAILED_EL, NVL(TRSTBC_ELIGIBLE_EL, 0) - NVL(TRSTBC_AVAILED_EL, 0) AS BALANCE_EL, TRSTBC_ELIGIBLE_ML AS ELIGIBLE_ML, TRSTBC_AVAILED_ML AS AVAILED_ML, NVL(TRSTBC_ELIGIBLE_ML, 0) - NVL(TRSTBC_AVAILED_ML, 0) AS BALANCE_ML, TRSTBC_ELIGIBLE_SL AS ELIGIBLE_SL, TRSTBC_AVAILED_SL AS AVAILED_SL, NVL(TRSTBC_ELIGIBLE_SL, 0) - NVL(TRSTBC_AVAILED_SL, 0) AS BALANCE_SL, TRSTBC_ELIGIBLE_CO AS ELIGIBLE_CO, TRSTBC_AVAILED_CO AS AVAILED_CO, NVL(TRSTBC_ELIGIBLE_CO, 0) - NVL(TRSTBC_AVAILED_CO, 0) AS BALANCE_CO, TRSTBC_ELIGIBLE_EX AS ELIGIBLE_EX, TRSTBC_AVAILED_EX AS AVAILED_EX, NVL(TRSTBC_ELIGIBLE_EX, 0) - NVL(TRSTBC_AVAILED_EX, 0) AS BALANCE_EX FROM trs.TRSTBC_ELIGIBLE_LEAVE WHERE TRSTBC_ADM_NO = :admno AND TRSTBC_YEAR = '2025'`;

    logger.info('Executing query', { query });

    const result = await connection.execute(query, { admno }, { outFormat: oracledb.OUT_FORMAT_OBJECT });
    logger.info('Query executed', { rowCount: result.rows?.length || 0 });

    if (!result.rows || result.rows.length === 0) {
      logger.warn('No leave balance found for employee', { admno });
      return res.status(200).json({
        success: true,
        data: {
          ELIGIBLE_CL: 0,
          AVAILED_CL: 0,
          BALANCE_CL: 0,
          ELIGIBLE_EL: 0,
          AVAILED_EL: 0,
          BALANCE_EL: 0,
          ELIGIBLE_ML: 0,
          AVAILED_ML: 0,
          BALANCE_ML: 0,
          ELIGIBLE_SL: 0,
          AVAILED_SL: 0,
          BALANCE_SL: 0,
          ELIGIBLE_CO: 0,
          AVAILED_CO: 0,
          BALANCE_CO: 0,
          ELIGIBLE_EX: 0,
          AVAILED_EX: 0,
          BALANCE_EX: 0,
          ELIGIBLE_OD: 0,
          AVAILED_OD: 0,
          BALANCE_OD: 0,
        },
      });
    }

    const leaveBalance = {
      ELIGIBLE_CL: result.rows[0].ELIGIBLE_CL || 0,
      AVAILED_CL: result.rows[0].AVAILED_CL || 0,
      BALANCE_CL: result.rows[0].BALANCE_CL || 0,
      ELIGIBLE_EL: result.rows[0].ELIGIBLE_EL || 0,
      AVAILED_EL: result.rows[0].AVAILED_EL || 0,
      BALANCE_EL: result.rows[0].BALANCE_EL || 0,
      ELIGIBLE_ML: result.rows[0].ELIGIBLE_ML || 0,
      AVAILED_ML: result.rows[0].AVAILED_ML || 0,
      BALANCE_ML: result.rows[0].BALANCE_ML || 0,
      ELIGIBLE_SL: result.rows[0].ELIGIBLE_SL || 0,
      AVAILED_SL: result.rows[0].AVAILED_SL || 0,
      BALANCE_SL: result.rows[0].BALANCE_SL || 0,
      ELIGIBLE_CO: result.rows[0].ELIGIBLE_CO || 0,
      AVAILED_CO: result.rows[0].AVAILED_CO || 0,
      BALANCE_CO: result.rows[0].BALANCE_CO || 0,
      ELIGIBLE_EX: result.rows[0].ELIGIBLE_EX || 0,
      AVAILED_EX: result.rows[0].AVAILED_EX || 0,
      BALANCE_EX: result.rows[0].BALANCE_EX || 0,
      ELIGIBLE_OD: 0,
      AVAILED_OD: 0,
      BALANCE_OD: 0,
    };

    logger.info(`Fetched leave balance for ADMNO ${admno}`, { leaveBalance });

    res.status(200).json({
      success: true,
      data: leaveBalance,
    });
  } catch (error) {
    logger.error('Error fetching leave balance', { error: error.message, stack: error.stack });
    res.status(500).json({
      success: false,
      message: 'Failed to fetch leave balance',
      error: error.message,
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
        logger.info('Database connection closed');
      } catch (err) {
        logger.error('Error closing database connection', { error: err.message });
      }
    }
  }
});

// Fetch leave types
app.get('/leave-types', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();
    const query = `
      SELECT DISTINCT lapmaa_leave_type AS code,
             DECODE(lapmaa_leave_type,
                    'CL', 'Casual Leave',
                    'ML', 'Medical Leave',
                    'EL', 'Earned Leave',
                    'CO', 'Compensatory Leave',
                    'EX', 'Extra Working',
                    'SL', 'Special Leave',
                    'LO', 'Loss of Pay',
                    lapmaa_leave_type) AS name
      FROM trs.lapmaa_request_master
      ORDER BY code
    `;
    const result = await connection.execute(query, {}, { outFormat: oracledb.OUT_FORMAT_OBJECT });
    res.status(200).json({
      success: true,
      data: result.rows,
    });
  } catch (error) {
    console.error('Error fetching leave types:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch leave types',
      error: error.message,
    });
  } finally {
    if (connection) {
      await connection.close().catch(err => console.error('Error closing connection:', err));
    }
  }
});



// Fetch all leave requests
app.get('/all-leave-requests', async (req, res) => {
  let connection;
  const { employeeId } = req.query;

  try {
    connection = await connectDb_dev();

    let query = `
      SELECT
        m.lapmaa_trans_id AS id,
        m.lapmaa_adm_no AS employeeId,
        NVL(p.epdmaa_name, 'Unknown') AS name,
        m.lapmaa_leave_type AS leaveType,
        NVL(d.epdmba_dept_name, 'Unknown') AS department,
        TO_CHAR(m.lapmaa_f_date, 'DD-MM-YYYY') AS startDate,
        TO_CHAR(m.lapmaa_t_date, 'DD-MM-YYYY') AS endDate,
        m.lapmaa_remarks AS reason,
        m.lapmaa_from_session AS fromSession,
        m.lapmaa_to_session AS toSession,
        od.trseps_trans_id AS medicalCertificateTransId,
        DECODE(m.lapmaa_leave_status,
               'P', 'PENDING',
               'A', 'PENDING',
               'G', 'APPROVED',
               'D', 'REJECTED',
               'C', 'CANCELED',
               'PENDING') AS status,
        m.lapmaa_total_days AS totalDays,
        TO_CHAR(m.lapmaa_applied_date, 'DD-MM-YYYY') AS lapmaa_applied_date,
        (SELECT COUNT(*) FROM trs.laptaa_request_detail d WHERE d.laptaa_trans_id = m.lapmaa_trans_id) AS hierarchyLevel,
        MAX(CASE WHEN d.laptaa_hierarchy_level = 1 THEN d.laptaa_hierarchy_head END) AS hierarchyHead1,
        MAX(CASE WHEN d.laptaa_hierarchy_level = 1 THEN
               DECODE(d.laptaa_status, 'N', 'PENDING', 'G', 'APPROVED', 'D', 'REJECTED', 'PENDING')
            END) AS approvalStatus1,
        MAX(CASE
            WHEN d.laptaa_hierarchy_level = 2
            AND (SELECT COUNT(*) FROM trs.laptaa_request_detail d2 WHERE d2.laptaa_trans_id = m.lapmaa_trans_id) >= 2
            AND (
              (m.lapmaa_leave_status IN ('P', 'A') AND d.laptaa_status = 'N') OR
              (m.lapmaa_leave_status = 'G' AND d.laptaa_status = 'G') OR
              (m.lapmaa_leave_status = 'D' AND d.laptaa_status = 'D')
            )
            AND EXISTS (
              SELECT 1 FROM trs.laptaa_request_detail d2
              WHERE d2.laptaa_trans_id = m.lapmaa_trans_id
              AND d2.laptaa_hierarchy_level = 1
              AND d2.laptaa_status = 'G'
            )
            THEN d.laptaa_hierarchy_head
            ELSE NULL
        END) AS hierarchyHead2,
        MAX(CASE
            WHEN d.laptaa_hierarchy_level = 2
            AND (SELECT COUNT(*) FROM trs.laptaa_request_detail d2 WHERE d2.laptaa_trans_id = m.lapmaa_trans_id) >= 2
            AND (
              (m.lapmaa_leave_status IN ('P', 'A') AND d.laptaa_status = 'N') OR
              (m.lapmaa_leave_status = 'G' AND d.laptaa_status = 'G') OR
              (m.lapmaa_leave_status = 'D' AND d.laptaa_status = 'D')
            )
            AND EXISTS (
              SELECT 1 FROM trs.laptaa_request_detail d2
              WHERE d2.laptaa_trans_id = m.lapmaa_trans_id
              AND d2.laptaa_hierarchy_level = 1
              AND d2.laptaa_status = 'G'
            )
            THEN DECODE(d.laptaa_status, 'N', 'PENDING', 'G', 'APPROVED', 'D', 'REJECTED', 'PENDING')
            ELSE NULL
        END) AS approvalStatus2,
        MAX(CASE
            WHEN d.laptaa_hierarchy_level = 3
            AND (SELECT COUNT(*) FROM trs.laptaa_request_detail d2 WHERE d2.laptaa_trans_id = m.lapmaa_trans_id) >= 3
            AND (
              (m.lapmaa_leave_status IN ('P', 'A') AND d.laptaa_status = 'N') OR
              (m.lapmaa_leave_status = 'G' AND d.laptaa_status = 'G') OR
              (m.lapmaa_leave_status = 'D' AND d.laptaa_status = 'D')
            )
            AND EXISTS (
              SELECT 1 FROM trs.laptaa_request_detail d2
              WHERE d2.laptaa_trans_id = m.lapmaa_trans_id
              AND d2.laptaa_hierarchy_level = 1
              AND d2.laptaa_status = 'G'
            )
            AND EXISTS (
              SELECT 1 FROM trs.laptaa_request_detail d3
              WHERE d3.laptaa_trans_id = m.lapmaa_trans_id
              AND d3.laptaa_hierarchy_level = 2
              AND d3.laptaa_status = 'G'
            )
            THEN d.laptaa_hierarchy_head
            ELSE NULL
        END) AS hierarchyHead3,
        MAX(CASE
            WHEN d.laptaa_hierarchy_level = 3
            AND (SELECT COUNT(*) FROM trs.laptaa_request_detail d2 WHERE d2.laptaa_trans_id = m.lapmaa_trans_id) >= 3
            AND (
              (m.lapmaa_leave_status IN ('P', 'A') AND d.laptaa_status = 'N') OR
              (m.lapmaa_leave_status = 'G' AND d.laptaa_status = 'G') OR
              (m.lapmaa_leave_status = 'D' AND d.laptaa_status = 'D')
            )
            AND EXISTS (
              SELECT 1 FROM trs.laptaa_request_detail d2
              WHERE d2.laptaa_trans_id = m.lapmaa_trans_id
              AND d2.laptaa_hierarchy_level = 1
              AND d2.laptaa_status = 'G'
            )
            AND EXISTS (
              SELECT 1 FROM trs.laptaa_request_detail d3
              WHERE d3.laptaa_trans_id = m.lapmaa_trans_id
              AND d3.laptaa_hierarchy_level = 2
              AND d3.laptaa_status = 'G'
            )
            THEN DECODE(d.laptaa_status, 'N', 'PENDING', 'G', 'APPROVED', 'D', 'REJECTED', 'PENDING')
            ELSE NULL
        END) AS approvalStatus3
      FROM trs.lapmaa_request_master m
      LEFT JOIN trs.laptaa_request_detail d ON m.lapmaa_trans_id = d.laptaa_trans_id
      LEFT JOIN trs.epdmaa_personal_details p ON m.lapmaa_adm_no = p.epdmaa_adm_no
      LEFT JOIN trs.epdmba_department d ON p.epdmaa_curr_dept_no = d.epdmba_dept_no
      LEFT JOIN trs.trseps_od_doc od ON (
        UPPER(od.trseps_trans_id) = UPPER(TRIM(m.lapmaa_leave_type) || LPAD(TRIM(TO_CHAR(m.lapmaa_adm_no)), 6, '0') || LPAD(TRIM(TO_CHAR(m.lapmaa_trans_id)), 3, '0'))
      )
    `;
    const binds = {};

    if (employeeId) {
      query += ` WHERE m.lapmaa_adm_no = :employeeId`;
      binds.employeeId = employeeId;
    }

    query += `
      GROUP BY
        m.lapmaa_trans_id, m.lapmaa_adm_no, p.epdmaa_name, m.lapmaa_leave_type,
        d.epdmba_dept_name, m.lapmaa_f_date, m.lapmaa_t_date, m.lapmaa_remarks,
        m.lapmaa_from_session, m.lapmaa_to_session, m.lapmaa_leave_status,
        m.lapmaa_total_days, m.lapmaa_applied_date, od.trseps_trans_id
      ORDER BY m.lapmaa_applied_date DESC
    `;

    const result = await connection.execute(query, binds, { outFormat: oracledb.OUT_FORMAT_OBJECT });

    const mappedData = await Promise.all(result.rows.map(async row => {
      let medicalCertificateBase64 = null;
      let medicalCertificateType = 'application/octet-stream';

      const rawLeaveType = row.LEAVETYPE;
      const rawEmployeeId = row.EMPLOYEEID;
      const rawTransId = row.ID;
      const constructedTransId = `${rawLeaveType}${String(rawEmployeeId).padStart(6, '0')}${String(rawTransId).padStart(3, '0')}`;
      console.log(`Row ID ${row.ID} Raw Values:`, {
        rawLeaveType,
        rawEmployeeId,
        rawTransId,
        constructedTransId,
        medicalCertificateTransId: row.MEDICALCERTIFICATETRANSID
      });

      if (row.MEDICALCERTIFICATETRANSID) {
        const docQuery = `
          SELECT trseps_od AS document, trseps_od_type AS documentType
          FROM trs.trseps_od_doc
          WHERE UPPER(trseps_trans_id) = UPPER(:transId)
        `;
        const docResult = await connection.execute(docQuery, { transId: row.MEDICALCERTIFICATETRANSID }, { outFormat: oracledb.OUT_FORMAT_OBJECT });

        console.log(`Document query result for transId ${row.MEDICALCERTIFICATETRANSID}:`, docResult.rows);

        if (docResult.rows.length > 0) {
          const { DOCUMENT, DOCUMENTTYPE } = docResult.rows[0];
          if (DOCUMENT && DOCUMENT.length > 0) {
            medicalCertificateBase64 = Buffer.from(DOCUMENT).toString('base64');
            console.log(`Document fetched for transId ${row.MEDICALCERTIFICATETRANSID}, base64 length:`, medicalCertificateBase64.length);
          } else {
            console.log(`No document data (BLOB is empty or NULL) for transId ${row.MEDICALCERTIFICATETRANSID}`);
          }
          medicalCertificateType = DOCUMENTTYPE || 'application/octet-stream';
        } else {
          console.log(`No document found in TRSEPS_OD_DOC for transId ${row.MEDICALCERTIFICATETRANSID}`);
        }
      } else {
        console.log(`No medicalCertificateTransId for row ID ${row.ID}`);
      }

      return {
        id: row.ID,
        name: row.NAME,
        employeeId: row.EMPLOYEEID,
        leaveType: row.LEAVETYPE,
        department: row.DEPARTMENT,
        startDate: row.STARTDATE,
        endDate: row.ENDDATE,
        reason: row.REASON,
        fromSession: row.FROMSESSION,
        toSession: row.TOSESSION,
        status: row.STATUS,
        totalDays: row.TOTALDAYS,
        hierarchyLevel: row.HIERARCHYLEVEL,
        hierarchyHead1: row.HIERARCHYHEAD1,
        approvalStatus1: row.APPROVALSTATUS1,
        hierarchyHead2: row.HIERARCHYHEAD2,
        approvalStatus2: row.APPROVALSTATUS2,
        hierarchyHead3: row.HIERARCHYHEAD3,
        approvalStatus3: row.APPROVALSTATUS3,
        medicalCertificateBase64: medicalCertificateBase64,
        medicalCertificateType: medicalCertificateType,
        medicalCertificateTransId: row.MEDICALCERTIFICATETRANSID,
        createdAt: row.LAPMAA_APPLIED_DATE,
      };
    }));

    console.log('Response data (first 3 rows):', mappedData.slice(0, 3).map(row => ({
      id: row.id,
      employeeId: row.employeeId,
      leaveType: row.leaveType,
      hierarchyLevel: row.hierarchyLevel,
      hierarchyHead1: row.hierarchyHead1,
      approvalStatus1: row.approvalStatus1,
      hierarchyHead2: row.hierarchyHead2,
      approvalStatus2: row.approvalStatus2,
      createdAt: row.createdAt,
      hasDocument: !!row.medicalCertificateBase64,
      base64Length: row.medicalCertificateBase64 ? row.medicalCertificateBase64.length : 0
    })));

    res.status(200).json({
      success: true,
      data: mappedData,
    });
  } catch (error) {
    console.error('Error fetching all leave requests:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch leave requests',
      error: error.message,
    });
  } finally {
    if (connection) {
      await connection.close().catch(err => console.error('Error closing connection:', err));
    }
  }
});

// Fetch leave requests for approval
app.get('/leave-requests', async (req, res) => {
  let connection;
  const { HeadId } = req.query;

  if (!HeadId) {
    return res.status(400).json({
      success: false,
      message: 'HeadId is required',
    });
  }

  try {
    connection = await connectDb_dev();

    const query = `
      SELECT
        m.lapmaa_trans_id AS id,
        m.lapmaa_adm_no AS employeeId,
        NVL(p.epdmaa_name, 'N/A') AS name,
        m.lapmaa_leave_type AS leaveType,
        NVL(d.epdmba_dept_name, 'N/A') AS department,
        TO_CHAR(m.lapmaa_f_date, 'DD-MM-YYYY') AS startDate,
        TO_CHAR(m.lapmaa_t_date, 'DD-MM-YYYY') AS endDate,
        m.lapmaa_remarks AS reason,
        m.lapmaa_from_session AS fromSession,
        m.lapmaa_to_session AS toSession,
        od.trseps_trans_id AS medicalCertificateTransId,
        od.trseps_od_type AS medicalCertificateType,
        DECODE(m.lapmaa_leave_status,
               'P', 'PENDING',
               'A', 'PENDING',
               'G', 'APPROVED',
               'D', 'REJECTED',
               'C', 'CANCELED',
               'PENDING') AS status,
        m.lapmaa_total_days AS totalDays,
        (SELECT COUNT(*) FROM trs.laptaa_request_detail d WHERE d.laptaa_trans_id = m.lapmaa_trans_id) AS hierarchyLevel,
        MAX(CASE WHEN d.laptaa_hierarchy_level = 1 THEN d.laptaa_hierarchy_head END) AS hierarchyHead1,
        MAX(CASE WHEN d.laptaa_hierarchy_level = 1 THEN
               DECODE(d.laptaa_status, 'N', 'PENDING', 'G', 'APPROVED', 'D', 'REJECTED', 'PENDING')
            END) AS approvalStatus1,
        MAX(CASE WHEN d.laptaa_hierarchy_level = 2 THEN d.laptaa_hierarchy_head END) AS hierarchyHead2,
        MAX(CASE WHEN d.laptaa_hierarchy_level = 2 THEN
               DECODE(d.laptaa_status, 'N', 'PENDING', 'G', 'APPROVED', 'D', 'REJECTED', 'PENDING')
            END) AS approvalStatus2,
        MAX(CASE WHEN d.laptaa_hierarchy_level = 3 THEN d.laptaa_hierarchy_head END) AS hierarchyHead3,
        MAX(CASE WHEN d.laptaa_hierarchy_level = 3 THEN
               DECODE(d.laptaa_status, 'N', 'PENDING', 'G', 'APPROVED', 'D', 'REJECTED', 'PENDING')
            END) AS approvalStatus3
      FROM trs.lapmaa_request_master m
      LEFT JOIN trs.laptaa_request_detail d ON m.lapmaa_trans_id = d.laptaa_trans_id
      LEFT JOIN trs.epdmaa_personal_details p ON m.lapmaa_adm_no = p.epdmaa_adm_no
      LEFT JOIN trs.epdmba_department d ON p.epdmaa_curr_dept_no = d.epdmba_dept_no
      LEFT JOIN trs.trseps_od_doc od ON (
        UPPER(od.trseps_trans_id) = UPPER(m.lapmaa_trans_id)
      )
      WHERE (
        (d.laptaa_hierarchy_level = 1 AND d.laptaa_hierarchy_head = :HeadId AND d.laptaa_status = 'N')
        OR (d.laptaa_hierarchy_level = 2 AND d.laptaa_hierarchy_head = :HeadId AND d.laptaa_status = 'N'
            AND EXISTS (
              SELECT 1 FROM trs.laptaa_request_detail d2
              WHERE d2.laptaa_trans_id = m.lapmaa_trans_id
              AND d2.laptaa_hierarchy_level = 1
              AND d2.laptaa_status = 'G'
            ))
        OR (d.laptaa_hierarchy_level = 3 AND d.laptaa_hierarchy_head = :HeadId AND d.laptaa_status = 'N'
            AND EXISTS (
              SELECT 1 FROM trs.laptaa_request_detail d2
              WHERE d2.laptaa_trans_id = m.lapmaa_trans_id
              AND d2.laptaa_hierarchy_level = 1
              AND d2.laptaa_status = 'G'
            )
            AND EXISTS (
              SELECT 1 FROM trs.laptaa_request_detail d3
              WHERE d3.laptaa_trans_id = m.lapmaa_trans_id
              AND d3.laptaa_hierarchy_level = 2
              AND d3.laptaa_status = 'G'
            ))
      )
      AND m.lapmaa_leave_status IN ('P', 'A')
      AND NOT EXISTS (
        SELECT 1
        FROM trs.lapmaa_request_master m2
        WHERE m2.lapmaa_trans_id = m.lapmaa_trans_id
        AND m2.lapmaa_leave_status = 'G'
        AND NOT EXISTS (
          SELECT 1
          FROM trs.laptaa_request_detail d3
          WHERE d3.laptaa_trans_id = m2.lapmaa_trans_id
          AND d3.laptaa_status = 'N'
        )
      )
      GROUP BY
        m.lapmaa_trans_id, m.lapmaa_adm_no, p.epdmaa_name, m.lapmaa_leave_type,
        d.epdmba_dept_name, m.lapmaa_f_date, m.lapmaa_t_date, m.lapmaa_remarks,
        m.lapmaa_from_session, m.lapmaa_to_session, m.lapmaa_leave_status,
        m.lapmaa_total_days, m.lapmaa_applied_date, od.trseps_trans_id,
        od.trseps_od_type
      ORDER BY m.lapmaa_applied_date DESC
    `;
    const binds = { HeadId };

    const result = await connection.execute(query, binds, { outFormat: oracledb.OUT_FORMAT_OBJECT });

    console.log('Query result:', {
      rowCount: result.rows.length,
      firstFewRows: result.rows.slice(0, 3).map(row => ({
        id: row.ID,
        employeeId: row.EMPLOYEEID,
        leaveType: row.LEAVETYPE,
        medicalCertificateTransId: row.MEDICALCERTIFICATETRANSID,
        status: row.STATUS
      }))
    });

    const mappedData = await Promise.all(result.rows.map(async row => {
      let medicalCertificateBase64 = null;
      let medicalCertificateType = row.MEDICALCERTIFICATETYPE || 'application/octet-stream';

      const rawLeaveType = row.LEAVETYPE;
      const rawEmployeeId = row.EMPLOYEEID;
      const rawTransId = row.ID;
      console.log(`Row ID ${row.ID} Raw Values:`, {
        rawLeaveType,
        rawEmployeeId,
        rawTransId,
        medicalCertificateTransId: row.MEDICALCERTIFICATETRANSID
      });

      if (row.MEDICALCERTIFICATETRANSID) {
        const docQuery = `
          SELECT trseps_od AS document
          FROM trs.trseps_od_doc
          WHERE UPPER(trseps_trans_id) = UPPER(:transId)
        `;
        const docResult = await connection.execute(docQuery, { transId: row.MEDICALCERTIFICATETRANSID }, { outFormat: oracledb.OUT_FORMAT_OBJECT });

        console.log(`Document query result for transId ${row.MEDICALCERTIFICATETRANSID}:`, docResult.rows);

        if (docResult.rows.length > 0) {
          const { DOCUMENT } = docResult.rows[0];
          if (DOCUMENT && DOCUMENT.length > 0) {
            console.log(`Raw BLOB length for transId ${row.MEDICALCERTIFICATETRANSID}:`, DOCUMENT.length);
            medicalCertificateBase64 = Buffer.from(DOCUMENT).toString('base64');
            console.log(`Document fetched for transId ${row.MEDICALCERTIFICATETRANSID}, base64 length:`, medicalCertificateBase64.length);
            console.log(`Base64 snippet for transId ${row.MEDICALCERTIFICATETRANSID}:`, medicalCertificateBase64.substring(0, 50));
          } else {
            console.log(`No document data (BLOB is empty or NULL) for transId ${row.MEDICALCERTIFICATETRANSID}`);
          }
        } else {
          console.log(`No document found in TRSEPS_OD_DOC for transId ${row.MEDICALCERTIFICATETRANSID}`);
        }
      } else {
        console.log(`No medicalCertificateTransId for row ID ${row.ID}`);
      }

      return {
        id: row.ID,
        name: row.NAME,
        employeeId: row.EMPLOYEEID,
        leaveType: row.LEAVETYPE,
        department: row.DEPARTMENT,
        startDate: row.STARTDATE,
        endDate: row.ENDDATE,
        reason: row.REASON,
        fromSession: row.FROMSESSION,
        toSession: row.TOSESSION,
        status: row.STATUS,
        totalDays: row.TOTALDAYS,
        hierarchyLevel: row.HIERARCHYLEVEL,
        hierarchyHead1: row.HIERARCHYHEAD1,
        approvalStatus1: row.APPROVALSTATUS1,
        hierarchyHead2: row.HIERARCHYHEAD2,
        approvalStatus2: row.APPROVALSTATUS2,
        hierarchyHead3: row.HIERARCHYHEAD3,
        approvalStatus3: row.APPROVALSTATUS3,
        medicalCertificateBase64: medicalCertificateBase64,
        medicalCertificateType: medicalCertificateType,
        medicalCertificateTransId: row.MEDICALCERTIFICATETRANSID
      };
    }));

    console.log('Response data (first 3 rows):', mappedData.slice(0, 3).map(row => ({
      id: row.id,
      employeeId: row.employeeId,
      leaveType: row.leaveType,
      hasDocument: !!row.medicalCertificateBase64,
      base64Length: row.medicalCertificateBase64 ? row.medicalCertificateBase64.length : 0
    })));

    res.status(200).json({
      success: true,
      data: mappedData,
    });
  } catch (error) {
    console.error('Error fetching leave requests:', {
      message: error.message,
      stack: error.stack,
      queryParams: { HeadId }
    });
    res.status(500).json({
      success: false,
      message: 'Failed to fetch leave requests',
      error: error.message,
    });
  } finally {
    if (connection) {
      await connection.close().catch(err => console.error('Error closing connection:', err));
    }
  }
});

// Endpoint to serve documents
app.get('/api/documents/:transId', async (req, res) => {
  let connection;
  const { transId } = req.params;

  try {
    connection = await connectDb_dev();

    const query = `
      SELECT trseps_od AS document, trseps_od_type AS documentType
      FROM trs.trseps_od_doc
      WHERE UPPER(trseps_trans_id) = UPPER(:transId)
    `;
    const binds = { transId };

    const result = await connection.execute(query, binds, { outFormat: oracledb.OUT_FORMAT_OBJECT });

    if (!result.rows || result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    const { DOCUMENT, DOCUMENTTYPE } = result.rows[0];

    if (!DOCUMENT) {
      return res.status(404).json({
        success: false,
        message: 'Document data is missing',
      });
    }

    const base64 = Buffer.from(DOCUMENT).toString('base64');
    res.status(200).json({
      success: true,
      data: {
        documentBase64: base64,
        documentType: DOCUMENTTYPE || 'application/octet-stream'
      }
    });
  } catch (error) {
    console.error('Error fetching document:', {
      message: error.message,
      stack: error.stack,
      transId
    });
    res.status(500).json({
      success: false,
      message: 'Failed to fetch document',
      error: error.message,
    });
  } finally {
    if (connection) {
      await connection.close().catch(err => console.error('Error closing connection:', err));
    }
  }
});

// Fetch pending requests count for a HeadId
app.get('/pending-requests', async (req, res) => {
  let connection;
  const { HeadId } = req.query;

  if (!HeadId) {
    return res.status(400).json({ success: false, message: 'HeadId is required' });
  }

  try {
    connection = await connectDb_dev();
    console.log(`Executing pending-requests query for HeadId: ${HeadId}`);

    const query = `
      SELECT COUNT(DISTINCT m.lapmaa_trans_id) AS pending_count
      FROM trs.lapmaa_request_master m
      JOIN trs.laptaa_request_detail d ON m.lapmaa_trans_id = d.laptaa_trans_id
      WHERE UPPER(DECODE(m.lapmaa_leave_status,
                         'P', 'PENDING',
                         'A', 'PENDING',
                         'G', 'APPROVED',
                         'D', 'REJECTED',
                         'C', 'CANCELED',
                         'PENDING')) = 'PENDING'
        AND (
          (d.laptaa_hierarchy_level = 1 AND d.laptaa_hierarchy_head = :HeadId AND d.laptaa_status = 'N')
          OR (d.laptaa_hierarchy_level = 2 AND d.laptaa_hierarchy_head = :HeadId AND d.laptaa_status = 'N'
              AND EXISTS (
                SELECT 1 FROM trs.laptaa_request_detail d2
                WHERE d2.laptaa_trans_id = m.lapmaa_trans_id
                AND d2.laptaa_hierarchy_level = 1
                AND d2.laptaa_status = 'G'
              ))
          OR (d.laptaa_hierarchy_level = 3 AND d.laptaa_hierarchy_head = :HeadId AND d.laptaa_status = 'N'
              AND EXISTS (
                SELECT 1 FROM trs.laptaa_request_detail d2
                WHERE d2.laptaa_trans_id = m.lapmaa_trans_id
                AND d2.laptaa_hierarchy_level = 1
                AND d2.laptaa_status = 'G'
              )
              AND EXISTS (
                SELECT 1 FROM trs.laptaa_request_detail d3
                WHERE d3.laptaa_trans_id = m.lapmaa_trans_id
                AND d3.laptaa_hierarchy_level = 2
                AND d3.laptaa_status = 'G'
              ))
        )
        AND NOT EXISTS (
          SELECT 1
          FROM trs.lapmaa_request_master m2
          WHERE m2.lapmaa_trans_id = m.lapmaa_trans_id
          AND m2.lapmaa_leave_status = 'G'
          AND NOT EXISTS (
            SELECT 1
            FROM trs.laptaa_request_detail d3
            WHERE d3.laptaa_trans_id = m2.lapmaa_trans_id
            AND d3.laptaa_status = 'N'
          )
        )
    `;

    const result = await connection.execute(
      query,
      { HeadId: { val: HeadId, type: oracledb.STRING } },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    console.log('Pending requests query result:', result);
    const pendingCount = result.rows[0]?.PENDING_COUNT || 0;
    res.status(200).json({ success: true, data: { pendingCount } });
  } catch (err) {
    console.error('Error fetching pending requests count:', err.message, err.stack);
    let errorMessage = err.message || 'Database error';
    if (err.message.includes('ORA-00942')) {
      errorMessage = `Database error: ORA-00942: table or view does not exist - Check if trs.lapmaa_request_master or trs.laptaa_request_detail exists`;
    } else if (err.message.includes('ORA-01722')) {
      errorMessage = `Database error: ORA-01722: invalid number - HeadId might not match the column data type`;
    }
    res.status(500).json({ success: false, message: errorMessage });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error('Error closing connection:', err);
      }
    }
  }
});

// Cancel a leave request
app.post('/cancel-leave/:transid', async (req, res) => {
  let connection;
  const { transid } = req.params;
  const { HeadId } = req.body;

  try {
    connection = await connectDb_dev();

    const authQuery = `
      SELECT 1
      FROM trs.lapmaa_request_master m
      WHERE m.lapmaa_trans_id = :transid
      AND (
        m.lapmaa_adm_no = :HeadId
        OR EXISTS (
          SELECT 1
          FROM trs.laptaa_request_detail d
          WHERE d.laptaa_trans_id = m.lapmaa_trans_id
          AND d.laptaa_hierarchy_head = :HeadId
        )
      )
    `;
    const authBinds = { transid, HeadId };
    const authResult = await connection.execute(authQuery, authBinds, { outFormat: oracledb.OUT_FORMAT_OBJECT });

    if (!authResult.rows.length) {
      return res.status(403).json({
        success: false,
        message: 'Unauthorized to cancel this leave request',
      });
    }

    const query = `
      BEGIN
        trs.LEAVE_APPLICATION.cancel_leave(:transid);
        COMMIT;
      END;
    `;
    const binds = { transid };

    await connection.execute(query, binds);

    res.status(200).json({
      success: true,
      message: 'Leave request canceled successfully',
    });
  } catch (error) {
    console.error('Error canceling leave request:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to cancel leave request',
      error: error.message,
    });
  } finally {
    if (connection) {
      await connection.close().catch(err => console.error('Error closing connection:', err));
    }
  }
});

// Accept a leave request
app.post("/accept-leave/:transId", async (req, res) => {
  const { transId } = req.params;
  const { HeadId } = req.body;

  let connection;
  try {
    if (!HeadId) {
      return res.status(400).json({
        success: false,
        message: 'HeadId is required',
      });
    }

    connection = await connectDb_dev();

    // Check if a record with this transId already exists in lapmaa_request_master with status 'APPROVED'
    const duplicateCheckQuery = `
      SELECT COUNT(*) AS count
      FROM trs.lapmaa_request_master
      WHERE lapmaa_trans_id = :transId
      AND lapmaa_leave_status = 'G'
    `;
    const duplicateCheckResult = await connection.execute(
      duplicateCheckQuery,
      { transId },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    const duplicateCount = duplicateCheckResult.rows[0].COUNT;
    console.log(`Duplicate check for transId ${transId}:`, {
      duplicateCount,
      transId,
    });

    if (duplicateCount > 0) {
      return res.status(409).json({
        success: false,
        message: `A leave record with transaction ID ${transId} is already approved.`,
        errorCode: 'DUPLICATE_LEAVE_TRANS_ID',
        transId,
      });
    }

    // Additional check: Verify if a record exists in trstbd_leave_details (or related table) with PK_TRSTBD_LEAVE_REF_NO
    const trstbdCheckQuery = `
      SELECT COUNT(*) AS count
      FROM trs.trstbd_leave_details
      WHERE trstbd_leave_ref_no = :transId
    `;
    const trstbdCheckResult = await connection.execute(
      trstbdCheckQuery,
      { transId },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    const trstbdCount = trstbdCheckResult.rows[0].COUNT;
    console.log(`TRSTBD check for transId ${transId}:`, {
      trstbdCount,
      transId,
    });

    if (trstbdCount > 0) {
      return res.status(409).json({
        success: false,
        message: `A leave record with transaction ID ${transId} already exists in leave details. Please contact support to resolve this conflict.`,
        errorCode: 'DUPLICATE_LEAVE_REF_NO',
        transId,
      });
    }

    // Verify if the HeadId is authorized to approve this request
    const authQuery = `
      SELECT
        d.laptaa_hierarchy_level,
        d.laptaa_status,
        (SELECT COUNT(*) FROM trs.laptaa_request_detail d2 WHERE d2.laptaa_trans_id = d.laptaa_trans_id) AS total_levels
      FROM trs.laptaa_request_detail d
      WHERE d.laptaa_trans_id = :transId
      AND d.laptaa_hierarchy_head = :HeadId
    `;
    const authResult = await connection.execute(authQuery, { transId, HeadId }, { outFormat: oracledb.OUT_FORMAT_OBJECT });

    if (!authResult.rows.length) {
      return res.status(403).json({
        success: false,
        message: 'Unauthorized to approve this leave request',
      });
    }

    const { LAPTAA_HIERARCHY_LEVEL, LAPTAA_STATUS, TOTAL_LEVELS } = authResult.rows[0];
    console.log(`Authorization check for transId ${transId}:`, {
      HeadId,
      hierarchyLevel: LAPTAA_HIERARCHY_LEVEL,
      currentStatus: LAPTAA_STATUS,
      totalLevels: TOTAL_LEVELS,
    });

    if (LAPTAA_STATUS !== 'N') {
      return res.status(400).json({
        success: false,
        message: 'Request is already processed at this level',
      });
    }

    // Check if previous levels are approved
    let canProceed = true;
    if (LAPTAA_HIERARCHY_LEVEL > 1) {
      const prevLevelQuery = `
        SELECT laptaa_status
        FROM trs.laptaa_request_detail
        WHERE laptaa_trans_id = :transId
        AND laptaa_hierarchy_level < :currentLevel
        ORDER BY laptaa_hierarchy_level DESC
      `;
      const prevLevelResult = await connection.execute(
        prevLevelQuery,
        { transId, currentLevel: LAPTAA_HIERARCHY_LEVEL },
        { outFormat: oracledb.OUT_FORMAT_OBJECT }
      );

      console.log(`Previous levels status for transId ${transId}:`, prevLevelResult.rows);

      canProceed = prevLevelResult.rows.every(row => row.LAPTAA_STATUS === 'G');
    }

    if (!canProceed) {
      return res.status(400).json({
        success: false,
        message: 'Cannot approve: Previous hierarchy levels are not yet approved',
      });
    }

    // Execute the grant_or_deny_leave procedure
    console.log(`Calling grant_or_deny_leave for transId ${transId} with HeadId ${HeadId}`);
    await connection.execute(
      `BEGIN trs.LEAVE_APPLICATION.grant_or_deny_leave(:transId, :headId, :action); COMMIT; END;`,
      {
        transId: transId,
        headId: HeadId,
        action: 'TRUE'
      },
      { autoCommit: true }
    );

    // Verify the status after approval
    const statusQuery = `
      SELECT lapmaa_leave_status, lapmaa_adm_no, lapmaa_leave_type
      FROM trs.lapmaa_request_master
      WHERE lapmaa_trans_id = :transId
    `;
    const statusResult = await connection.execute(statusQuery, { transId }, { outFormat: oracledb.OUT_FORMAT_OBJECT });
    const { LAPMAA_LEAVE_STATUS, LAPMAA_ADM_NO, LAPMAA_LEAVE_TYPE } = statusResult.rows[0] || {};
    console.log(`Post-approval status for transId ${transId}:`, {
      leaveStatus: LAPMAA_LEAVE_STATUS,
      employeeId: LAPMAA_ADM_NO,
      leaveType: LAPMAA_LEAVE_TYPE,
    });

    // Check if the request is fully approved (all hierarchy levels)
    const approvalStatusQuery = `
      SELECT laptaa_hierarchy_level, laptaa_status
      FROM trs.laptaa_request_detail
      WHERE laptaa_trans_id = :transId
    `;
    const approvalStatusResult = await connection.execute(
      approvalStatusQuery,
      { transId },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    console.log(`Approval status for transId ${transId}:`, approvalStatusResult.rows);

    res.status(200).json({
      success: true,
      message: 'Leave request accepted successfully',
      finalStatus: LAPMAA_LEAVE_STATUS,
    });
  } catch (error) {
    console.error(`Error accepting leave request transId ${transId}:`, {
      message: error.message,
      stack: error.stack,
      HeadId,
    });

    let errorMessage = error.message || 'Failed to accept leave request';
    let errorCode = 'GENERIC_ERROR';
    if (error.message.includes('ORA-00001')) {
      errorMessage = `A leave record with transaction ID ${transId} already exists. Please contact support to resolve this conflict.`;
      errorCode = 'DUPLICATE_LEAVE_TRANS_ID';
    } else if (error.message.includes('ORA-')) {
      errorMessage = `Database error: ${error.message}`;
      errorCode = 'DATABASE_ERROR';
    }

    res.status(500).json({
      success: false,
      message: errorMessage,
      error: error.message,
      errorCode,
      transId,
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error('Error closing connection:', err);
      }
    }
  }
});

// Reject a leave request
app.post("/reject-leave/:transId", async (req, res) => {
  const { transId } = req.params;
  const { HeadId } = req.body;

  let connection;
  try {
    connection = await connectDb_dev();

    await connection.execute(
      `BEGIN trs.LEAVE_APPLICATION.grant_or_deny_leave(:transId, :headId, :action); COMMIT; END;`,
      {
        transId: transId,
        headId: HeadId,
        action: 'FALSE'
      },
      { autoCommit: true }
    );

    res.status(200).json({
      success: true,
      message: 'Leave request rejected successfully'
    });
  } catch (error) {
    console.error("Error rejecting leave request:", error);
    res.status(500).json({
      success: false,
      message: error.message || "Failed to reject leave request"
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing connection:", err);
      }
    }
  }
});

// Fetch leave history for a specific employee
app.get('/employee-leave-history/:employeeId', async (req, res) => {
  let connection;
  const { employeeId } = req.params;

  try {
    connection = await connectDb_dev();

    const query = `
      SELECT
        m.lapmaa_trans_id AS id,
        m.lapmaa_adm_no AS employeeId,
        NVL(p.epdmaa_name, 'Unknown') AS name,
        m.lapmaa_leave_type AS leaveType,
        NVL(d.epdmba_dept_name, 'Unknown') AS department,
        TO_CHAR(m.lapmaa_f_date, 'DD-MM-YYYY') AS startDate,
        TO_CHAR(m.lapmaa_t_date, 'DD-MM-YYYY') AS endDate,
        m.lapmaa_from_session AS fromSession,
        m.lapmaa_to_session AS toSession,
        m.lapmaa_remarks AS reason,
        NULL AS document,
        DECODE(m.lapmaa_leave_status,
               'P', 'PENDING',
               'A', 'PENDING',
               'G', 'APPROVED',
               'D', 'REJECTED',
               'C', 'CANCELED',
               'PENDING') AS status,
        m.lapmaa_total_days AS totalDays,
        TO_CHAR(m.lapmaa_applied_date, 'DD-MM-YYYY') AS createdAt
      FROM trs.lapmaa_request_master m
      LEFT JOIN trs.epdmaa_personal_details p ON m.lapmaa_adm_no = p.epdmaa_adm_no
      LEFT JOIN trs.epdmba_department d ON p.epdmaa_curr_dept_no = d.epdmba_dept_no
      WHERE m.lapmaa_adm_no = :employeeId
      ORDER BY m.lapmaa_applied_date DESC
    `;
    const result = await connection.execute(query, { employeeId }, { outFormat: oracledb.OUT_FORMAT_OBJECT });

    const mappedData = result.rows.map(row => ({
      id: row.ID,
      employeeId: row.EMPLOYEEID,
      name: row.NAME,
      department: row.DEPARTMENT,
      leaveType: row.LEAVETYPE,
      startDate: row.STARTDATE,
      endDate: row.ENDDATE,
      fromSession: row.FROMSESSION,
      toSession: row.TOSESSION,
      reason: row.REASON,
      document: row.DOCUMENT,
      status: row.STATUS,
      totalDays: row.TOTALDAYS,
      createdAt: row.CREATEDAT,
    }));

    res.status(200).json({
      success: true,
      data: mappedData,
    });
  } catch (error) {
    console.error('Error fetching employee leave history:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch employee leave history',
      error: error.message,
    });
  } finally {
    if (connection) {
      await connection.close().catch(err => console.error('Error closing connection:', err));
    }
  }
});


// Fetch Extra Work Status Endpoint (Updated)
app.get('/extra-work-status/:employeeId', async (req, res) => {
  let connection;
  try {
    const { employeeId } = req.params;
    connection = await connectDb_dev();

    const result = await connection.execute(
      `SELECT transaction_id, lapmaa_leave_type, lapmaa_request_type, lapmaa_from_date, lapmaa_to_date,
              lapmaa_total_days, lapmaa_reason, lapmaa_leave_status
       FROM trs.lapmaa_request_master
       WHERE lapmaa_employee_id = :employee_id
         AND lapmaa_leave_type = 'CO'`,
      { employee_id: employeeId },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: `Failed to fetch extra work status: ${err.message}` });
  } finally {
    if (connection) await connection.close();
  }
});

// Fetch Overtime Status Endpoint (Updated)
app.get('/overtime-status/:employeeId', async (req, res) => {
  let connection;
  try {
    const { employeeId } = req.params;
    connection = await connectDb_dev();

    const result = await connection.execute(
      `SELECT lapmaa_trans_id, lapmaa_leave_type, lapmaa_request_type, lapmaa_f_date, lapmaa_t_date,
          lapmaa_total_days, lapmaa_remarks, lapmaa_leave_status, lapmaa_from_time, lapmaa_to_time
   FROM trs.lapmaa_request_master
   WHERE lapmaa_adm_no = :employee_id
     AND lapmaa_leave_type = 'EX'`,
      { employee_id: employeeId },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: `Failed to fetch overtime status: ${err.message}` });
  } finally {
    if (connection) await connection.close();
  }
});

// Fetch Extra Work Applications for Admin (Updated)
app.get('/admin/extra-work-applications', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();

    const result = await connection.execute(
      `SELECT m.lapmaa_trans_id, m.lapmaa_adm_no, m.lapmaa_leave_type, m.lapmaa_request_type,
          m.lapmaa_f_date, m.lapmaa_t_date, m.lapmaa_total_days, m.lapmaa_remarks,
          m.lapmaa_leave_status, m.lapmaa_from_session, m.lapmaa_to_session,
          NVL(p.epdmaa_name, 'Unknown') AS employee_name,
          NVL(d.epdmba_dept_name, 'Unknown') AS department_name,
          p.epdmaa_designation AS designation
   FROM trs.lapmaa_request_master m
   LEFT JOIN trs.epdmaa_personal_details p ON m.lapmaa_adm_no = p.epdmaa_adm_no
   LEFT JOIN trs.epdmba_department d ON p.epdmaa_curr_dept_no = d.epdmba_dept_no
   WHERE m.lapmaa_leave_type = 'CO'
     AND m.lapmaa_leave_status = 'P'`,
      {},
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: `Failed to fetch extra work applications: ${err.message}` });
  } finally {
    if (connection) await connection.close();
  }
});

// Fetch Overtime Applications for Admin (Updated)
app.get('/admin/overtime-applications', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();

    const result = await connection.execute(
      `SELECT m.lapmaa_trans_id, m.lapmaa_adm_no, m.lapmaa_leave_type, m.lapmaa_request_type,
          m.lapmaa_f_date, m.lapmaa_t_date, m.lapmaa_total_days, m.lapmaa_remarks,
          m.lapmaa_leave_status, m.lapmaa_from_time, m.lapmaa_to_time,
          NVL(p.epdmaa_name, 'Unknown') AS employee_name,
          NVL(d.epdmba_dept_name, 'Unknown') AS department_name,
          p.epdmaa_designation AS designation
   FROM trs.lapmaa_request_master m
   LEFT JOIN trs.epdmaa_personal_details p ON m.lapmaa_adm_no = p.epdmaa_adm_no
   LEFT JOIN trs.epdmba_department d ON p.epdmaa_curr_dept_no = d.epdmba_dept_no
   WHERE m.lapmaa_leave_type = 'EX'
     AND m.lapmaa_leave_status = 'P'`,
      {},
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: `Failed to fetch overtime applications: ${err.message}` });
  } finally {
    if (connection) await connection.close();
  }
});


// Approve Extra Work/Overtime Endpoint (Updated)
app.post('/approve-extra-work/:id', async (req, res) => {
  let connection;
  try {
    const { id } = req.params;
    const { action, remarks, grantingHead } = req.body;

    // Validate action and grantingHead
    if (!action || !['approve', 'reject'].includes(action)) {
      logger.warn('Invalid action', { action });
      return res.status(400).json({ success: false, message: 'Invalid action. Must be "approve" or "reject"' });
    }
    if (!grantingHead) {
      logger.warn('Missing grantingHead', { grantingHead });
      return res.status(400).json({ success: false, message: 'Granting head is required' });
    }

    connection = await connectDb_dev();
    logger.info('Connected to database for approving extra work', { transId: id });

    // Fetch the application details
    const applicationResult = await connection.execute(
      `SELECT lapmaa_adm_no, lapmaa_leave_type, lapmaa_f_date, lapmaa_t_date,
              lapmaa_total_days, lapmaa_remarks
       FROM trs.lapmaa_request_master
       WHERE lapmaa_trans_id = :trans_id`,
      { trans_id: id },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    if (!applicationResult.rows || applicationResult.rows.length === 0) {
      logger.warn('Application not found', { transId: id });
      return res.status(404).json({ success: false, message: 'Application not found' });
    }

    const application = applicationResult.rows[0];
    const { LAPMAA_ADM_NO, LAPMAA_LEAVE_TYPE, LAPMAA_F_DATE, LAPMAA_T_DATE, LAPMAA_TOTAL_DAYS, LAPMAA_REMARKS } = application;
    logger.info('Fetched application details', { application });

    // Validate leave type
    if (!['CO', 'EX'].includes(LAPMAA_LEAVE_TYPE)) {
      logger.warn('Invalid leave type for approval', { leaveType: LAPMAA_LEAVE_TYPE });
      return res.status(400).json({ success: false, message: 'This endpoint is only for CO and EX leave types' });
    }

    // Call grant_or_deny_leave
    await connection.execute(
      `BEGIN
         trs.leave_application.grant_or_deny_leave(
           :trans_id,
           :granting_head,
           :action,
           :remarks
         );
         COMMIT;
       END;`,
      {
        trans_id: id,
        granting_head: grantingHead,
        action: action === 'approve' ? 'TRUE' : 'FALSE',
        remarks: remarks?.slice(0, 500).trim() || ''
      },
      { autoCommit: true }
    );
    logger.info('Executed grant_or_deny_leave procedure', { transId: id, action });

    // If approved, handle EX leave by calling EXTRA_LEAVE
    if (action === 'approve' && LAPMAA_LEAVE_TYPE === 'EX') {
      await connection.execute(
        `BEGIN
           trs.EXTRA_LEAVE(
             :ref_no,
             :adm_no,
             :total_day,
             TO_DATE(:valid_from, 'YYYY-MM-DD'),
             :reason
           );
           COMMIT;
         END;`,
        {
          ref_no: id, // Use transaction ID as reference number
          adm_no: LAPMAA_ADM_NO,
          total_day: LAPMAA_TOTAL_DAYS,
          valid_from: LAPMAA_F_DATE.toISOString().split('T')[0], // Convert to YYYY-MM-DD
          reason: LAPMAA_REMARKS || 'No reason provided'
        },
        { autoCommit: true }
      );
      logger.info('Executed EXTRA_LEAVE procedure for EX leave', { transId: id, admNo: LAPMAA_ADM_NO });
    }

    res.status(200).json({ success: true, message: `Application ${action}d successfully` });
  } catch (err) {
    logger.error('Error in approve-extra-work', { error: err.message, stack: err.stack });
    if (err.message.includes('ORA-20003')) {
      const specificError = err.message.match(/ORA-20003: (.+?)(ORA-|$)/)?.[1] || 'Failed to record extra work request.';
      return res.status(400).json({ success: false, message: specificError });
    }
    if (err.message.includes('FORM_TRIGGER_FAILURE')) {
      return res.status(400).json({
        success: false,
        message: 'Approval/Rejection failed due to a server-side validation error. Please check the application details.',
      });
    }
    res.status(500).json({ success: false, message: `Failed to process application: ${err.message}` });
  } finally {
    if (connection) {
      try {
        await connection.close();
        logger.info('Database connection closed');
      } catch (closeError) {
        logger.error('Error closing connection', { error: closeError.message });
      }
    }
  }
});

// Reject Extra Work/Overtime Endpoint (Updated)
app.post('/reject-extra-work/:id', async (req, res) => {
  let connection;
  try {
    const { id } = req.params;
    const { grantingHead, remarks } = req.body;

    if (!grantingHead) {
      return res.status(400).json({ success: false, message: 'Granting head is required' });
    }

    connection = await connectDb_dev();

    await connection.execute(
      `BEGIN
         trs.leave_application.grant_or_deny_leave(
           :transId,
           :grantingHead,
           'FALSE',
           :remarks
         );
       END;`,
      {
        transId: id,
        grantingHead: grantingHead,
        remarks: remarks || ''
      }
    );

    await connection.commit();
    res.status(200).json({ success: true, message: 'Application rejected successfully' });
  } catch (err) {
    if (connection) await connection.rollback();
    let errorMessage = err.message;
    if (err.message.includes('FORM_TRIGGER_FAILURE')) {
      errorMessage = 'Rejection failed due to a server-side validation error. Please check the application details.';
    }
    res.status(500).json({ success: false, message: errorMessage });
  } finally {
    if (connection) await connection.close();
  }
});

// Notify Admin Endpoint (Placeholder)
app.post('/notify-admin', async (req, res) => {
  try {
    const { userId, type } = req.body;
    // Placeholder for notification logic (e.g., send email, push notification)
    console.log(`Notifying admin about ${type} application from user ${userId}`);
    res.status(200).json({ success: true, message: 'Admin notified successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: `Failed to notify admin: ${err.message}` });
  }
});



// Fetch all CL and OT requests
app.get('/all-cl-ot-requests', async (req, res) => {
  let connection;
  try {
    connection = await connectDb_dev();
    const result = await connection.execute(
      `SELECT lapmaa_trans_id, lapmaa_adm_no, lapmaa_leave_type, lapmaa_f_date,
              lapmaa_t_date, lapmaa_total_days, lapmaa_remarks, lapmaa_leave_status,
              lapmaa_from_time, lapmaa_to_time
       FROM trs.lapmaa_request_master
       WHERE lapmaa_leave_type IN ('CO', 'EX')`,
      {},
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
   
    const applications = result.rows.map(row => ({
      transactionId: row.LAPMAA_TRANS_ID,
      employeeId: row.LAPMAA_ADM_NO,
      leaveType: row.LAPMAA_LEAVE_TYPE,
      fromDate: row.LAPMAA_F_DATE,
      toDate: row.LAPMAA_T_DATE,
      totalDays: row.LAPMAA_TOTAL_DAYS,
      reason: row.LAPMAA_LEAVE_TYPE === 'CO' ? row.LAPMAA_REMARKS : undefined,
      taskDescription: row.LAPMAA_LEAVE_TYPE === 'EX' ? row.LAPMAA_REMARKS : undefined,
      status: row.LAPMAA_LEAVE_STATUS === 'P' ? 'Pending' : row.LAPMAA_LEAVE_STATUS === 'G' ? 'Granted' : 'Rejected',
      fromTime: row.LAPMAA_FROM_TIME,
      toTime: row.LAPMAA_TO_TIME
    }));

    res.status(200).json({
      success: true,
      data: applications
    });
  } catch (err) {
    console.error('Error in all-cl-ot-requests:', err);
    res.status(500).json({
      success: false,
      message: `Error fetching CL/OT requests: ${err.message}`
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error('Error closing connection:', err);
      }
    }
  }
});

app.get('/trainers', async (req, res) => {
  let connection;
  
  try {
    connection = await connectDb_dev();
    
    // Query to fetch past training records where FEEDBACK_DATE is before today
    const query = `
    SELECT DISTINCT EPDMAA_NAME, EPDMAA_ADM_NO
FROM TRS.EPDMAA_PERSONAL_DETAILS 
WHERE EPDMAA_DOR IS NULL
ORDER BY EPDMAA_ADM_NO ASC `; // Fetch only past training feedback

    // Execute query (No bind variables needed)
    const result = await connection.execute(query, [], { 
      outFormat: oracledb.OUT_FORMAT_OBJECT 
    });
    
    // Check if any records were found
    if (!result.rows || result.rows.length === 0) {
      return res.status(200).json({
        success: true,
        count: 0,
        data: []
      });
    }
    
    // Send success response
    res.status(200).json({ 
      success: true, 
      count: result.rows.length,
      data: result.rows 
    });
    
  } catch (error) {
    console.error("Error fetching training history:", error);
    res.status(500).json({ 
      success: false, 
      error: error.message || "Error fetching training history" 
    });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing database connection:", err);
      }
    }
  }
});

// Logout API
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: 'Error logging out' });
    }
    res.clearCookie('connect.sid'); // Clear session cookie
    return res.status(200).json({ message: 'Logged out successfully' });
  });
});

// app.listen(port, '0.0.0.0', (err) => {
//   if (err) {
//     console.error('Failed to start server:', err);
//     process.exit(1);
//   }
//   console.log(`Server running at http://localhost:${port}`);
//   console.log(`Server running on http://192.168.90.221:${port}`);
// });

// async function callOvertimeHrCalc(admNo, otDate) {
//   let connection;

//   try {
//     // Establish connection to the database
//     connection = await connectDb_dev();
//     console.log('Connected to Oracle database');

//     // Format otDate to Oracle DATE format (DD-MON-YYYY)
//     const formattedDate = moment(otDate).format('DD-MMM-YYYY');

//     // Prepare the SQL statement to call the stored procedure
//     const sql = `
//       BEGIN
//         OVERTIME_HR_CALC(:adm_no, TO_DATE(:ot_date, 'DD-MON-YYYY'));
//       END;
//     `;

//     // Bind parameters
//     const binds = {
//       adm_no: { val: admNo, type: oracledb.NUMBER },
//       ot_date: { val: formattedDate, type: oracledb.STRING }
//     };

//     // Execute the stored procedure
//     await connection.execute(sql, binds, { autoCommit: true });
//     console.log(`Successfully executed OVERTIME_HR_CALC for ADM_NO: ${admNo}, OT_DATE: ${formattedDate}`);

//   } catch (err) {
//     console.error('Error executing stored procedure:', err);
//     throw err;
//   } finally {
//     // Close the connection
//     if (connection) {
//       try {
//         await connection.close();
//         console.log('Database connection closed');
//       } catch (err) {
//         console.error('Error closing connection:', err);
//       }
//     }
//   }
// }

// // Example usage
// async function main() {
//   const admNo = 12345; // Replace with actual employee ID
//   const otDate = '2025-05-16'; // Replace with desired overtime date (YYYY-MM-DD)

//   try {
//     await callOvertimeHrCalc(admNo, otDate);
//   } catch (err) {
//     console.error('Failed to process overtime calculation:', err);
//   }
// }

// // Run the script
// main();

app.listen(5000, '0.0.0.0', (err) => {
    if (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
  console.log('Server running on http://192.168.90.221:5000');
});
