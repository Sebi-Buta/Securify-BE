import express, { type Request, type Response } from "express";
import cors from "cors";
import mongoose, { Schema, Document } from "mongoose";
import bcrypt from "bcrypt";

const app = express();

app.use(cors());
// Permitem Express să citească JSON (acest lucru e esențial pentru NoSQL Injection)
app.use(express.json());

// ---------------------------------------------------------
// 1. CONEXIUNEA LA MONGODB
// ---------------------------------------------------------
const mongoURI = "mongodb+srv://seblaur09_db_user:SecurifyPassword@securify.nwtmqgu.mongodb.net/?appName=Securify";

mongoose.connect(mongoURI)
	.then(() => console.log("🟢 Conectat cu succes la MongoDB!"))
	.catch((err) => console.error("🔴 Eroare la conectarea MongoDB:", err));

// ---------------------------------------------------------
// 2. DEFINIREA SCHEMELOR MONGODB (Modele & Interfețe TS)
// ---------------------------------------------------------

// A. Modelul pentru User
interface IUser extends Document {
	username: string;
	password?: string; // Aici va sta hash-ul
	role: string;
}

const UserSchema = new Schema<IUser>({
	username: { type: String, required: true, unique: true },
	password: { type: String, required: true },
	role: { type: String, default: "user" },
});
const UserModel = mongoose.model<IUser>("User", UserSchema);

// B. Modelul pentru Comentarii (XSS)
interface IComment extends Document {
	author: string;
	content: string;
	createdAt: Date;
}

const CommentSchema = new Schema<IComment>({
	author: { type: String, required: true },
	content: { type: String, required: true },
	createdAt: { type: Date, default: Date.now },
});
const CommentModel = mongoose.model<IComment>("Comment", CommentSchema);

// ---------------------------------------------------------
// PASUL 1: RUTA DE STATUS
// ---------------------------------------------------------
app.get("/api/status", (req: Request, res: Response) => {
	res.json({ message: "Serverul TS+MongoDB este online!" });
});

// ---------------------------------------------------------
// PASUL 2: NoSQL INJECTION (Autentificare)
// ---------------------------------------------------------

// A. Ruta VULNERABILĂ (Atac NoSQLi)
app.post("/api/login-vulnerable", async (req: Request, res: Response): Promise<void> => {
	try {
		// GRAV: Trimitem direct req.body.username în baza de date.
		// Dacă atacatorul trimite { "username": {"$ne": null}, "password": {"$ne": null} },
		// MongoDB va evalua asta ca fiind ADEVĂRAT și va returna primul user (adminul)!

		const user = await UserModel.findOne({
			username: req.body.username,
			password: req.body.password,
		});

		if (user) {
			res.json({ success: true, message: "HACKED! Autentificare reușită!", user });
		} else {
			res.status(401).json({ success: false, message: "User sau parolă incorecte." });
		}
	} catch (error: any) {
		res.status(500).json({ error: error.message });
	}
});

// B. Ruta SECURIZATĂ (Apărare)
app.post("/api/login-secure", async (req: Request, res: Response): Promise<void> => {
	try {
		// CORECT: Forțăm datele să fie de tip String.
		// Dacă un hacker trimite un obiect {"$ne": null}, String() îl va transforma în textul "[object Object]",
		// distrugând astfel atacul NoSQLi.
		const safeUsername = String(req.body.username);
		const safePassword = String(req.body.password);

		if (!safeUsername || !safePassword) {
			res.status(400).json({ success: false, message: "Te rog introdu datele." });
			return;
		}

		// Căutăm doar după username
		const user = await UserModel.findOne({ username: safeUsername });

		if (user) {
			// Verificăm parola cu bcrypt
			const match = await bcrypt.compare(safePassword, user.password || "");

			if (match) {
				// Nu returnăm parola hash-uită către frontend
				const userObj = user.toObject();
				delete userObj.password;

				res.json({ success: true, message: "Autentificare sigură reușită!", user: userObj });
			} else {
				res.status(401).json({ success: false, message: "Parolă incorectă." });
			}
		} else {
			res.status(401).json({ success: false, message: "Userul nu există." });
		}
	} catch (error: any) {
		res.status(500).json({ error: error.message });
	}
});

// ---------------------------------------------------------
// PASUL 3: CROSS-SITE SCRIPTING (Comentarii)
// ---------------------------------------------------------
app.post("/api/comments", async (req: Request, res: Response): Promise<void> => {
	try {
		const { author, content } = req.body;
		const newComment = new CommentModel({ author, content });
		await newComment.save(); // Salvăm documentul în MongoDB

		res.json({ success: true, message: "Comentariu adăugat." });
	} catch (error: any) {
		res.status(500).json({ error: error.message });
	}
});

app.get("/api/comments", async (req: Request, res: Response): Promise<void> => {
	try {
		// .find() scoate toate documentele, .sort() le ordonează descrescător
		const comments = await CommentModel.find().sort({ createdAt: -1 });
		res.json(comments);
	} catch (error: any) {
		res.status(500).json({ error: error.message });
	}
});

// ---------------------------------------------------------
// PASUL 4: CRIPTOGRAFIE & GESTIUNE (Creare user cu Hashing)
// ---------------------------------------------------------
app.post("/api/users", async (req: Request, res: Response): Promise<void> => {
	try {
		const { username, password } = req.body;

		if (!username || !password) {
			res.status(400).json({ error: "Username și parola sunt obligatorii." });
			return;
		}

		const saltRounds = 10;
		const hashedPassword = await bcrypt.hash(String(password), saltRounds);

		const newUser = new UserModel({
			username: String(username),
			password: hashedPassword,
		});

		await newUser.save();
		res.json({ success: true, message: "Utilizator creat în siguranță!" });
	} catch (error: any) {
		// Prindem eroarea dacă userul există deja (unique: true)
		if (error.code === 11000) {
			res.status(400).json({ error: "Acest username este deja folosit." });
		} else {
			res.status(500).json({ error: error.message });
		}
	}
});

// ---------------------------------------------------------
// PORNIREA SERVERULUI
// ---------------------------------------------------------
const PORT = 5000;
app.listen(PORT, () => {
	console.log(`🛡️ Serverul TS+MongoDB rulează pe portul ${PORT}`);
});
