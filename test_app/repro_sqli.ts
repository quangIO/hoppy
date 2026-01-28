import express, { Request, Response } from 'express';
const { Client } = require('pg');

const app = express();
app.use(express.json());

const client = new Client();

app.post('/sqli', async (req: Request, res: Response) => {
    const userId = req.body.id;
    // Classic SQLi
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    const result = await client.query(query);
    res.json(result.rows);
});

app.listen(3000);
