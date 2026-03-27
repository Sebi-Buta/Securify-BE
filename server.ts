import express, { type Request, type Response } from "express";
import cors from "cors";
import mysql, { type RowDataPacket } from "mysql2/promise";
import { type ResultSetHeader } from "mysql2";
import bcrypt from "bcrypt";

const app = express();

app.use(cors());
app.use(express.json());

// ---------------------------------------------------------
// DEFINIREA TIPURILOR DE DATE (Interfețe)
// Asta arată comisiei că știi arhitectură software!
// ---------------------------------------------------------

interface LoginRequest {
	username?: string;
	password?: string;
}

interface CommentRequest {
	author?: string;
	content?: string;
}

interface UserRequest {
	username?: string;
	password?: string;
}

// ---------------------------------------------------------
// CONEXIUNEA LA BAZA DE DATE
// ---------------------------------------------------------
const dbConfig: mysql.ConnectionOptions = {
	host: "localhost",
	user: "root",
	password: "",
	database: "securify_db",
};

// ---------------------------------------------------------
// PASUL 1: RUTA DE STATUS
// ---------------------------------------------------------
app.get("/api/status", (req: Request, res: Response) => {
	res.json({ message: "Serverul TS este online și gata de atac/apărare!" });
});

// ---------------------------------------------------------
// PASUL 2: SQL INJECTION (Autentificare)
// ---------------------------------------------------------

// A. Ruta VULNERABILĂ (Atac)
app.post("/api/login-vulnerable", async (req: Request<{}, {}, LoginRequest>, res: Response): Promise<void> => {
	const { username, password } = req.body;

	try {
		const connection = await mysql.createConnection(dbConfig);
		const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

		// <RowDataPacket[]> îi spune lui TS ce fel de date returnează baza de date
		const [rows] = await connection.execute<RowDataPacket[]>(query);
		await connection.end();

		if (rows.length > 0) {
			res.json({ success: true, message: "Autentificare reușită!", user: rows[0] });
		} else {
			res.status(401).json({ success: false, message: "User sau parolă incorecte." });
		}
	} catch (error: any) {
		res.status(500).json({ error: error.message });
	}
});

// B. Ruta SECURIZATĂ (Apărare)
app.post("/api/login-secure", async (req: Request<{}, {}, LoginRequest>, res: Response): Promise<void> => {
	// 1. Preluăm datele trimise din interfața React
	const { username, password } = req.body;

	// Verificăm dacă a introdus ambele câmpuri
	if (!username || !password) {
		res.status(400).json({ success: false, message: "Te rog introdu user și parolă." });
		return;
	}

	try {
		const connection = await mysql.createConnection(dbConfig);

		// 2. CĂUTĂM DOAR DUPĂ USERNAME (Nu verificăm parola în SQL)
		const query = `SELECT * FROM users WHERE username = ?`;
		const [rows] = await connection.execute<RowDataPacket[]>(query, [username]);
		await connection.end();

		// Verificăm dacă userul există în baza de date
		if (rows.length > 0) {
			const user = rows[0]; // Extragem datele userului găsit

			// 3. MAGIA: Lăsăm bcrypt să compare parola scrisă cu Hash-ul din DB
			// 'password' e ce a scris omul, 'user.password' e hash-ul stocat
			const match = await bcrypt.compare(password, user?.password);

			if (match) {
				// Parola este corectă!
				// Best practice: Nu trimite parola înapoi către frontend
				const { password: _, ...userWithoutPassword }: any = user;

				res.json({
					success: true,
					message: "Autentificare reușită!",
					user: userWithoutPassword,
				});
			} else {
				// Parola este greșită
				res.status(401).json({ success: false, message: "Parolă incorectă." });
			}
		} else {
			// Userul nu a fost găsit deloc
			res.status(401).json({ success: false, message: "Acest user nu există." });
		}
	} catch (error: any) {
		res.status(500).json({ error: error.message });
	}
});

// ---------------------------------------------------------
// PASUL 3: CROSS-SITE SCRIPTING (Comentarii)
// ---------------------------------------------------------

app.post("/api/comments", async (req: Request<{}, {}, CommentRequest>, res: Response): Promise<void> => {
	const { author, content } = req.body;

	try {
		const connection = await mysql.createConnection(dbConfig);
		const [result] = await connection.execute<ResultSetHeader>({
			sql: "INSERT INTO comments (author, content) VALUES (?, ?)",
			values: [author, content],
		});
		await connection.end();
		res.json({ success: true, message: "Comentariu adăugat." });
	} catch (error: any) {
		res.status(500).json({ error: error.message });
	}
});

app.get("/api/comments", async (req: Request, res: Response): Promise<void> => {
	try {
		const connection = await mysql.createConnection(dbConfig);
		const [rows] = await connection.execute<RowDataPacket[]>("SELECT * FROM comments ORDER BY created_at DESC");
		await connection.end();
		res.json(rows);
	} catch (error: any) {
		res.status(500).json({ error: error.message });
	}
});

// ---------------------------------------------------------
// PASUL 4: CRIPTOGRAFIE & GESTIUNE (Creare user cu Hashing)
// ---------------------------------------------------------
app.post("/api/users", async (req: Request<{}, {}, UserRequest>, res: Response): Promise<void> => {
	const { username, password } = req.body;

	if (!username || !password) {
		res.status(400).json({ error: "Username și parola sunt obligatorii." });
		return;
	}

	try {
		const saltRounds = 10;
		const hashedPassword = await bcrypt.hash(password, saltRounds);

		const connection = await mysql.createConnection(dbConfig);
		await connection.execute("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword]);
		await connection.end();

		res.json({ success: true, message: "Utilizator creat în siguranță!" });
	} catch (error: any) {
		res.status(500).json({ error: error.message });
	}
});

// ---------------------------------------------------------
// PORNIREA SERVERULUI
// ---------------------------------------------------------
const PORT = 5000;
app.listen(PORT, () => {
	console.log(`🛡️ Serverul TS Securify rulează pe portul ${PORT}`);
});
