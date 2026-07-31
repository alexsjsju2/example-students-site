const admin = require('firebase-admin');
const crypto = require('crypto');

if (!admin.apps.length) {
    try {
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
    } catch (error) {
        console.error(error);
    }
}

const db = admin.firestore();
const hash = str => crypto.createHash('sha256').update(String(str)).digest('hex');

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', 'https://www.alexsjsju.eu');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    try {
        if (req.method === 'POST') {
            const { action, name, password, secretKey, data, newName, newPassword } = req.body;

            if (action === 'register') {
                if (!name || name.length < 3 || name.length > 20 || !password || password.length < 4) {
                    return res.status(400).json({ error: "Nome (3-20 car.) o Password (min 4 car.) non validi" });
                }
                const cleanName = name.replace(/[^a-zA-Z0-9_]/g, '');
                const ref = db.collection('planner_users').doc(cleanName);
                if ((await ref.get()).exists) return res.status(400).json({ error: "Nome utente già esistente" });

                const generatedSecret = crypto.randomBytes(12).toString('hex');
                await ref.set({
                    name: cleanName,
                    password: hash(password),
                    secretKey: hash(generatedSecret),
                    plannerData: { timetable: {}, reminders: [], notes: [], votes: [] },
                    lastUpdated: admin.firestore.FieldValue.serverTimestamp()
                });
                return res.status(200).json({ secretKey: generatedSecret, name: cleanName, plannerData: { timetable: {}, reminders: [], notes: [], votes: [] } });
            }

            if (action === 'login') {
                const cleanName = (name || '').replace(/[^a-zA-Z0-9_]/g, '');
                const ref = db.collection('planner_users').doc(cleanName);
                const doc = await ref.get();
                if (!doc.exists) return res.status(404).json({ error: "Utente non trovato" });
                const userData = doc.data();
                if (userData.password !== hash(password)) return res.status(401).json({ error: "Password errata" });
                return res.status(200).json({ name: userData.name, plannerData: userData.plannerData || { timetable: {}, reminders: [], notes: [], votes: [] } });
            }

            if (action === 'update') {
                if (!secretKey) return res.status(400).json({ error: "Chiave di sicurezza richiesta" });
                const snap = await db.collection('planner_users').where('secretKey', '==', hash(secretKey)).limit(1).get();
                if (snap.empty) return res.status(401).json({ error: "Chiave di sicurezza non valida" });

                const userDoc = snap.docs[0];
                const oldData = userDoc.data();
                const updates = {};

                if (newPassword && newPassword.length >= 4) updates.password = hash(newPassword);

                if (newName && newName !== oldData.name) {
                    const cleanNewName = newName.replace(/[^a-zA-Z0-9_]/g, '');
                    if (cleanNewName.length < 3 || cleanNewName.length > 20) return res.status(400).json({ error: "Nuovo nome non valido" });
                    const checkRef = db.collection('planner_users').doc(cleanNewName);
                    if ((await checkRef.get()).exists) return res.status(400).json({ error: "Nome già in uso" });

                    await checkRef.set({ ...oldData, ...updates, name: cleanNewName });
                    await userDoc.ref.delete();
                    return res.status(200).json({ message: "Credenziali aggiornate!", newName: cleanNewName });
                }

                if (Object.keys(updates).length > 0) await userDoc.ref.update(updates);
                return res.status(200).json({ message: "Credenziali aggiornate!", newName: oldData.name });
            }

            if (action === 'saveData') {
                const cleanName = (name || '').replace(/[^a-zA-Z0-9_]/g, '');
                const userRef = db.collection('planner_users').doc(cleanName);
                const userDoc = await userRef.get();
                if (userDoc.exists) {
                    await userRef.update({
                        plannerData: data,
                        lastUpdated: admin.firestore.FieldValue.serverTimestamp()
                    });
                    return res.status(200).json({ message: "Dati salvati con successo" });
                }
                return res.status(404).json({ error: "Utente non trovato" });
            }

            return res.status(400).json({ error: "Azione non valida" });
        }
        return res.status(405).json({ error: "Metodo non consentito" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "Errore interno del server" });
    }
}
