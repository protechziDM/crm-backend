const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const dotenv = require('dotenv');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs').promises;
const winston = require('winston');

dotenv.config();

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
    ],
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.simple(),
    }));
}

const app = express();
const port = process.env.PORT || 5000;
const secretKey = process.env.JWT_SECRET || 'yourSecretKey';

app.use(cors());
app.use(express.json({ limit: '50mb' }));

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

function createCrudEndpoints(tableName, routeName) {
    app.get(`/api/${routeName}`, async (req, res) => {
        try {
            const [rows] = await pool.query(`SELECT * FROM ${tableName}`);
            res.json(rows);
        } catch (err) {
            logger.error(`Error fetching ${routeName}:`, err);
            res.status(500).json({ error: `Failed to fetch ${routeName}`, details: err.message });
        }
    });

    app.post(`/api/${routeName}`, async (req, res) => {
        try {
            const { name } = req.body;
            const [result] = await pool.query(`INSERT INTO ${tableName} (name) VALUES (?)`, [name]);
            res.json({ message: `${routeName} added`, id: result.insertId });
        } catch (err) {
            logger.error(`Error adding ${routeName}:`, err);
            res.status(500).json({ error: `Failed to add ${routeName}`, details: err.message });
        }
    });

    app.delete(`/api/${routeName}/:id`, async (req, res) => {
        try {
            const { id } = req.params;
            await pool.query(`DELETE FROM ${tableName} WHERE id = ?`, [id]);
            res.json({ message: `${routeName} deleted` });
        } catch (err) {
            logger.error(`Error deleting ${routeName}:`, err);
            res.status(500).json({ error: `Failed to delete ${routeName}`, details: err.message });
        }
    });

    app.put(`/api/${routeName}/:id`, async (req, res) => {
        try {
            const { id } = req.params;
            const { name } = req.body;
            await pool.query(`UPDATE ${tableName} SET name = ? WHERE id = ?`, [name, id]);
            res.json({ message: `${routeName} updated` });
        } catch (err) {
            logger.error(`Error updating ${routeName}:`, err);
            res.status(500).json({ error: `Failed to update ${routeName}`, details: err.message });
        }
    });
}

createCrudEndpoints('lead_types', 'lead-types');
createCrudEndpoints('lead_statuses', 'lead-statuses');
createCrudEndpoints('services_availed', 'services-availed');
createCrudEndpoints('lead_sources', 'lead-sources');
createCrudEndpoints('hosted_on', 'hosted-on');
createCrudEndpoints('lead_earned_by', 'lead-earned-by');
createCrudEndpoints('paymenttype', 'payment-types');
createCrudEndpoints('paymentprocessor', 'payment-processors');

app.get('/api/countries', async (req, res) => {
    try {
        const filePath = path.join(__dirname, 'countries.json');
        const data = await fs.readFile(filePath, 'utf8');
        const countries = JSON.parse(data);
        res.json(countries);
    } catch (err) {
        logger.error('Error:', err);
        res.status(500).json({ error: 'Failed to fetch countries' });
    }
});

app.post('/api/leads', async (req, res) => {
    try {
        const leadData = req.body;
        const connection = await pool.getConnection();
        const columns = Object.keys(leadData).join(', ');
        const values = Object.values(leadData);

        if (leadData.lead_status_id === '') { leadData.lead_status_id = null; values[columns.split(', ').indexOf('lead_status_id')] = null; }
        if (leadData.hosted_on_id === '') { leadData.hosted_on_id = null; values[columns.split(', ').indexOf('hosted_on_id')] = null; }
        if (leadData.service_availed_id === '') { leadData.service_availed_id = null; values[columns.split(', ').indexOf('service_availed_id')] = null; }
        if (leadData.lead_source_id === '') { leadData.lead_source_id = null; values[columns.split(', ').indexOf('lead_source_id')] = null; }
        if (leadData.lead_earned_by_id === '') { leadData.lead_earned_by_id = null; values[columns.split(', ').indexOf('lead_earned_by_id')] = null; }

        const placeholders = values.map(() => '?').join(', ');
        const sql = `INSERT INTO leads (${columns}) VALUES (${placeholders})`; // Corrected line - NO HTML TAGS
        const [result] = await connection.query(sql, values);
        connection.release();
        res.json({ message: 'Lead created successfully' });
    } catch (err) {
        logger.error('Error creating lead:', err);
        res.status(500).json({ error: 'Failed to create lead', details: err.message });
    }
});

app.get('/api/leads/monthly-earned', async (req, res) => {
    const query = `
        SELECT
            lead_earned_by_id,
            DATE_FORMAT(post_date, '%Y-%m-01') AS month,
            COUNT(*) AS leadCount
        FROM
            leads
        WHERE
            post_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
        GROUP BY
            lead_earned_by_id,
            DATE_FORMAT(post_date, '%Y-%m-01')
        ORDER BY
            lead_earned_by_id,
            month;
    `;

    try {
        const [results] = await pool.query(query); // Use await here
        res.json(results);
    } catch (err) {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Internal server error', details: err.message });
    }
});

app.post('/api/notes', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        await connection.execute('INSERT INTO notes (lead_id, message, author_id) VALUES (?, ?, ?)', [req.body.lead_id, req.body.message, req.body.author_id]);
        connection.release();
        res.status(201).json({ message: 'Note added successfully' });
    } catch (error) {
        logger.error('Error adding note:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/notes/:lead_id', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        const [notes] = await connection.execute('SELECT * FROM notes WHERE lead_id = ?', [req.params.lead_id]);
        connection.release();
        res.json(notes);
    } catch (error) {
        logger.error('Error fetching notes:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/notes/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const connection = await pool.getConnection();
        await connection.execute('DELETE FROM notes WHERE id = ?', [id]);
        connection.release();
        res.json({ message: 'Note deleted successfully' });
    } catch (error) {
        logger.error('Error deleting note:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/register', async (req, res) => {
    const { username, password, user_type } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)', [username, hashedPassword, user_type]);
        res.json({ message: 'User registered successfully' });
    } catch (error) {
        logger.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user', details: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const user = rows[0];

        // Check if the account is blocked
        if (user.login_attempts >= 5) {
            return res.status(401).json({ error: 'Account locked due to too many failed login attempts. Contact Admin' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (passwordMatch) {
            // Check if the account is not blocked before resetting login_attempts
            if (user.login_attempts < 5) {
                try {
                    await pool.query('UPDATE users SET login_attempts = 0 WHERE id = ?', [user.id]);
                } catch (updateError) {
                    logger.error("error with successful login update query: ", updateError);
                }
            }
            const token = jwt.sign({ userId: user.id, userType: user.user_type }, secretKey, { expiresIn: '1h' });
            res.json({ token, user: { id: user.id, type: user.user_type, name: user.name, login_attempts: 0 } });
        } else {
            try {
                await pool.query('UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?', [user.id]);
            } catch (updateError) {
                logger.error("error with failed login update query: ", updateError);
            }
            try {
                const [updatedUserRows] = await pool.query('SELECT login_attempts FROM users WHERE id = ?', [user.id]);
                const updatedUser = updatedUserRows[0];
                if (updatedUser.login_attempts >= 5) {
                    return res.status(401).json({ error: 'Account locked due to too many failed login attempts. Contact Admin' });
                }
                res.status(401).json({ error: 'Invalid credentials' });
            } catch (selectError) {
                logger.error("error with select query: ", selectError);
            }
        }
    } catch (error) {
        logger.error('Error logging in:', error);
        res.status(500).json({ error: 'Failed to log in', details: error.message });
    }
});

app.post('/api/users', async (req, res) => {
    try {
        const { username, name, password, user_type } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.query('INSERT INTO users (username, name, password, user_type, login_attempts) VALUES (?, ?, ?, ?, ?)', [username, name, hashedPassword, user_type, 0]);
        res.json({ message: 'User added successfully', id: result.insertId });
    } catch (err) {
        logger.error('Error adding user:', err);
        res.status(500).json({ error: 'Failed to add user', details: err.message });
    }
});

app.get('/api/users', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, username, name, user_type, login_attempts FROM users');
        res.json(rows);
    } catch (err) {
        logger.error('Error fetching users:', err);
        res.status(500).json({ error: 'Failed to fetch users', details: err.message });
    }
});

app.get('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT name FROM users WHERE id = ?', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(rows[0]);
    } catch (err) {
        logger.error('Error fetching user:', err);
        res.status(500).json({ error: 'Failed to fetch user', details: err.message });
    }
});

app.put('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { username, name, user_type } = req.body;
        await pool.query('UPDATE users SET username = ?, name = ?, user_type = ? WHERE id = ?', [username, name, user_type, id]);
        res.json({ message: 'User updated successfully' });
    } catch (err) {
        logger.error('Error updating user:', err);
        res.status(500).json({ error: 'Failed to update user', details: err.message });
    }
});

app.delete('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('DELETE FROM users WHERE id = ?', [id]);
        res.json({ message: 'User deleted successfully' });
    } catch (err) {
        logger.error('Error deleting user:', err);
        res.status(500).json({ error: 'Failed to delete user', details: err.message });
    }
});

app.put('/api/users/password/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, id]);
        res.json({ message: 'Password updated successfully' });
    } catch (err) {
        logger.error('Error updating password:', err);
        res.status(500).json({ error: 'Failed to update password', details: err.message });
    }
});

app.put('/api/users/status/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        await pool.query('UPDATE users SET login_attempts = ? WHERE id = ?', [status, id]);
        res.json({ message: 'Status updated successfully' });
    } catch (err) {
        logger.error('Error updating status:', err);
        res.status(500).json({ error: 'Failed to update status', details: err.message });
    }
});

app.get('/api/leads/count', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT COUNT(*) as count FROM leads');
        res.json({ count: rows[0].count });
    } catch (error) {
        logger.error('Error fetching lead count:', error);
        res.status(500).json({ error: 'Failed to fetch lead count', details: error.message });
    }
});

app.put('/api/leads/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const leadData = req.body;

        // Remove service_x from leadData
        Object.keys(leadData).forEach(key => {
            if (key.startsWith('service_')) {
                delete leadData[key];
            }
        });

        const connection = await pool.getConnection();
        const setClauses = Object.keys(leadData).map((key) => `${key} = ?`).join(', ');
        const values = Object.values(leadData);
        values.push(id);
        const sql = `UPDATE leads SET ${setClauses} WHERE id = ?`;
        const [result] = await connection.query(sql, values);
        connection.release();
        res.json({ message: 'Lead updated successfully' });
    } catch (err) {
        logger.error('Error updating lead:', err);
        res.status(500).json({ error: 'Failed to update lead', details: err.message });
    }
});

app.delete('/api/leads/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const connection = await pool.getConnection();
        await connection.query('DELETE FROM leads WHERE id = ?', [id]);
        connection.release();
        res.json({ message: 'Lead deleted successfully' });
    } catch (err) {
        logger.error('Error deleting lead:', err);
        res.status(500).json({ error: 'Failed to delete lead', details: err.message });
    }
});

const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        req.user = decoded;
        next();
    });
};

app.get('/api/validate-token', verifyToken, (req, res) => {
    res.json({ message: 'Token is valid', user: req.user });
});

app.get('/api/leads/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const [rows] = await pool.query('SELECT * FROM leads WHERE author_id = ?', [userId]);
        res.json(rows);
    } catch (err) {
        logger.error('Error fetching user-specific leads:', err);
        res.status(500).json({ error: 'Failed to fetch user-specific leads', details: err.message });
    }
});

app.get('/api/leads/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT * FROM leads WHERE id = ?', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Lead not found' });
        }
        res.json(rows[0]);
    } catch (err) {
        logger.error('Error fetching lead:', err);
        res.status(500).json({ error: 'Failed to fetch lead', details: err.message });
    }
});

app.get('/api/leads', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        const [rows] = await connection.query('SELECT * FROM leads');
        connection.release();
        res.json(rows);
    } catch (err) {
        logger.error('Error fetching leads:', err);
        res.status(500).json({ error: 'Failed to fetch leads', details: err.message });
    }
});

app.get('/api/leads-archive', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        const [rows] = await connection.query('SELECT * FROM leads_archive');
        connection.release();
        res.json(rows);
    } catch (err) {
        logger.error('Error fetching leads archives:', err);
        res.status(500).json({ error: 'Failed to fetch leads archives', details: err.message });
    }
});

const isAdmin = (req, res, next) => {
    if (req.user && req.user.userType === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Forbidden: Admin privileges required' });
    }
};

app.post('/api/payments', verifyToken, async (req, res) => {
    try {
        const { lead_id, payment_type_id, amount, payment_source_id, due_date, author_id, received_date, remarks } = req.body;
        if (!lead_id || !payment_type_id || !amount || !payment_source_id || !author_id) {
            return res.status(400).json({ message: 'Missing required fields' });
        }
        const [result] = await pool.query('INSERT INTO Payments (lead_id, payment_type_id, amount, payment_source_id, due_date, author_id, created_at, remarks) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [lead_id, payment_type_id, amount, payment_source_id, due_date, author_id, received_date, remarks]);
        res.status(201).json({ message: 'Payment added successfully', paymentId: result.insertId });
    } catch (error) {
        logger.error('Error adding payment:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/payments', async (req, res) => {
    try {
        const connection = await pool.getConnection();

        // Pagination parameters
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 30; // Default limit 30
        const offset = (page - 1) * limit;

        // Filter and Search parameters
        const search = req.query.search || '';
        const paymentType = req.query.paymentType || '';
        const startDate = req.query.startDate || '';
        const endDate = req.query.endDate || '';
        const period = req.query.period || '';
        const status = req.query.status || ''; // Add status parameter

        // Construct the WHERE clause based on filters and search
        let whereClause = 'WHERE 1=1'; // Start with a true condition

        if (search) {
            whereClause += ` AND (leads.name LIKE '%${search}%' OR leads.lead_no LIKE '%${search}%')`;
        }

        if (paymentType) {
            whereClause += ` AND payments.payment_type_id = ${paymentType}`;
        }

        if (startDate && endDate) {
            whereClause += ` AND payments.created_at BETWEEN '${startDate}' AND '${endDate}'`;
        } else if (startDate) {
            whereClause += ` AND payments.created_at >= '${startDate}'`;
        } else if (endDate) {
            whereClause += ` AND payments.created_at <= '${endDate}'`;
        }

        if (period) {
            // Implement your period filter logic here
            // Example: Assuming period is in "YYYY-MM" format
            const [year, month] = period.split('-');
            if (year && month) {
                whereClause += ` AND YEAR(payments.due_date) = ${year} AND MONTH(payments.due_date) = ${month}`;
            }
        }

        if (status) { // Add status filter
            whereClause += ` AND payments.status = '${status}'`;
        }

        // Fetch paginated payments with lead names
        const [rows] = await connection.query(`
            SELECT payments.*, leads.name AS lead_name
            FROM payments
            JOIN leads ON payments.lead_id = leads.id
            ${whereClause}
            ORDER BY payments.created_at DESC
            LIMIT ? OFFSET ?
        `, [limit, offset]);

        // Fetch total items for pagination
        const [totalItemsResult] = await connection.query(`
            SELECT COUNT(*) AS totalItems
            FROM payments
            JOIN leads ON payments.lead_id = leads.id
            ${whereClause}
        `);

        const totalItems = totalItemsResult[0].totalItems;
        const totalPages = Math.ceil(totalItems / limit);

        connection.release();

        res.json({
            payments: rows,
            totalPages: totalPages,
            totalItems: totalItems,
        });

    } catch (err) {
        logger.error('Error fetching payments with lead names:', err);
        res.status(500).json({ error: 'Failed to fetch payments with lead names', details: err.message });
    }
});

app.delete('/api/payments/trash/:id', verifyToken, async (req, res) => {
    try {
        const paymentId = req.params.id;
        const userId = req.user.userId;
        const userType = req.user.userType;

        // Get the lead ID associated with the payment
        const [paymentRows] = await pool.query('SELECT lead_id FROM Payments WHERE payment_id = ?', [paymentId]);

        if (paymentRows.length === 0) {
            return res.status(404).json({ message: 'Payment not found' });
        }

        const leadId = paymentRows[0].lead_id;

        // Get the author ID of the lead
        const [leadRows] = await pool.query('SELECT author_id FROM leads WHERE id = ?', [leadId]);

        if (leadRows.length === 0) {
            return res.status(404).json({ message: 'Lead not found' });
        }

        const leadAuthorId = leadRows[0].author_id;

        // Check permissions: admin or lead author
        if (userType === 1 || userId === leadAuthorId) {
            // Soft delete: update the status to 'trash'
            await pool.query('UPDATE Payments SET status = ? WHERE payment_id = ?', ['trash', paymentId]);
            res.json({ message: 'Payment marked as trash successfully' });
        } else {
            return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
        }
    } catch (error) {
        logger.error('Error marking payment as trash:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.delete('/api/payments/delete/:id', verifyToken, async (req, res) => {
    try {
        const paymentId = req.params.id;
        const userId = req.user.userId;
        const userType = req.user.userType;

        // Get the lead ID associated with the payment
        const [paymentRows] = await pool.query('SELECT lead_id FROM Payments WHERE payment_id = ?', [paymentId]);

        if (paymentRows.length === 0) {
            return res.status(404).json({ message: 'Payment not found' });
        }

        const leadId = paymentRows[0].lead_id;

        // Get the author ID of the lead
        const [leadRows] = await pool.query('SELECT author_id FROM leads WHERE id = ?', [leadId]);

        if (leadRows.length === 0) {
            return res.status(404).json({ message: 'Lead not found' });
        }

        const leadAuthorId = leadRows[0].author_id;

        // Check permissions: admin or lead author
        if (userType === 1 || userId === leadAuthorId) {
            // Permanently delete the payment
            await pool.query('DELETE FROM Payments WHERE payment_id = ?', [paymentId]);
            res.json({ message: 'Payment permanently deleted successfully' });
        } else {
            return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
        }
    } catch (error) {
        logger.error('Error permanently deleting payment:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/payments/lead/:leadId', verifyToken, async (req, res) => {
    try {
        const leadId = req.params.leadId;
        const status = req.query.status; // Get the status from the query parameters

        if (!status) {
            return res.status(400).json({ message: 'Status parameter is required.' });
        }

        const [rows] = await pool.query('SELECT * FROM Payments WHERE lead_id = ? AND status = ?', [leadId, status]);
        res.json(rows);
    } catch (error) {
        logger.error('Error getting payments for lead:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.put('/api/payments/:id', verifyToken, async (req, res) => {
    try {
        const paymentId = req.params.id;
        const { lead_id, payment_type_id, amount, payment_source_id, due_date, created_at, remarks, status } = req.body;
        const userId = req.user.userId;
        const userType = req.user.userType;

        // Get the lead ID associated with the payment
        const [leadRows] = await pool.query('SELECT author_id FROM leads WHERE id = ?', [lead_id]);

        if (leadRows.length === 0) {
            console.log("Lead not found for lead_id:", lead_id);
            return res.status(404).json({ message: 'Lead not found' });
        }

        const leadAuthorId = leadRows[0].author_id;

        if (userType === 1 || userId === leadAuthorId) {
            const updateQuery = 'UPDATE Payments SET lead_id = ?, payment_type_id = ?, amount = ?, payment_source_id = ?, due_date = ?, created_at = ?, remarks = ?, status = ? WHERE payment_id = ?';
            const updateValues = [lead_id, payment_type_id, amount, payment_source_id, due_date, created_at, remarks, status, paymentId];

            await pool.query(updateQuery, updateValues);
            res.json({ message: 'Payment updated successfully' });
        } else {
            console.log("Forbidden: Insufficient permissions for userId:", userId, "userType:", userType);
            return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
        }
    } catch (error) {
        console.error("Error updating payment:", error); // Log the error
        res.status(500).json({ message: 'Internal server error', error: error.message }); // Send error message and details
    }
});

app.get('/api/lead-services', verifyToken, async (req, res) => {
    try {
        const [results] = await pool.query(
            'SELECT lead_id, service_id FROM lead_services'
        );
        res.json(results); // Send the array of lead_id and service_id objects
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// GET /api/lead-services/:leadId
app.get('/api/lead-services/:leadId', verifyToken, async (req, res) => {
    const { leadId } = req.params;

    try {
        const [results] = await pool.query(
            'SELECT service_id FROM lead_services WHERE lead_id = ?',
            [leadId]
        );
        const serviceIds = results.map(row => row.service_id); // Extract service IDs
        res.json(serviceIds); // Send the array of service IDs
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/api/lead-services/:leadId', verifyToken, async (req, res) => {
    const { leadId } = req.params;
    const { services } = req.body;

    try {
        const connection = await pool.getConnection();
        await connection.beginTransaction();

        await connection.query('DELETE FROM lead_services WHERE lead_id = ?', [leadId]);

        if (services && services.length > 0) {
            for (const serviceId of services) {
                await connection.query(
                    'INSERT INTO lead_services (lead_id, service_id) VALUES (?, ?)',
                    [leadId, serviceId]
                );
            }
        }

        await connection.commit();
        connection.release();

        res.json({ message: 'Lead services updated successfully' });
    } catch (err) {
        if (connection) {
            await connection.rollback();
            connection.release();
        }
        logger.error('Error updating lead services:', err);
        res.status(500).json({ error: 'Internal Server Error', details: err.message });
    }
});

app.post('/api/leads-archive', async (req, res) => {
    try {
        const leadData = req.body;
        await pool.query('INSERT INTO leads_archive SET ?', leadData);
        res.status(201).send({ message: 'Lead archived successfully' });
    } catch (error) {
        console.error('Error archiving lead:', error);
        res.status(500).send({ error: 'Failed to archive lead' });
    }
});

app.delete('/api/leads-archive/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('DELETE FROM leads_archive WHERE id = ?', [id]);
        res.json({ message: 'Lead deleted from archive successfully' });
    } catch (err) {
        logger.error('Error deleting lead from archive:', err);
        res.status(500).json({ error: 'Failed to delete lead from archive', details: err.message });
    }
});

app.get('/api/lead-earned-by', async (req, res) => {
    pool.query('SELECT id, name FROM lead_earned_by', (err, results) => {
        if (err) {
            console.error('Database error:', err);
            res.status(500).json({ error: 'Internal server error' });
            return;
        }
        res.json(results); // Corrected MySQL access
    });
});



// Endpoint for regular users (user-specific count)
app.get('/api/leads/count/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const [rows] = await pool.query('SELECT COUNT(*) as count FROM leads WHERE author_id = ?', [userId]);
        res.json({ count: rows[0].count });
    } catch (error) {
        logger.error('Error fetching user-specific lead count:', error);
        res.status(500).json({ error: 'Failed to fetch user-specific lead count', details: error.message });
    }
});

app.use((req, res) => {
    res.status(404).send('Not found');
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});