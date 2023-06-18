import express from 'express';
import bodyParser from 'body-parser';
import fs from 'fs';
import crypto from 'crypto';
import { fromWBXML, toWBXML, nodeText } from './utils.js';
import { SwuotaServer } from './SwuotaServer.js';

process.env.NODE_ENV = 'production';

const SERVER_AUTH = [
	{
		login:				"swuota_user",
		password:			"swuota",
		server_login:		"SWUOTA",
		server_password:	"swuota"
	}, {
		login:				"mobile",
		password:			"diagnose",
		server_login:		"DIAGNOSE",
		server_password:	"diagnose"
	}
];

let devices = {};

let app = express();
app.use(bodyParser.raw({
	inflate: true,
	limit: '100kb',
	type: 'application/vnd.syncml.dm+wbxml'
}));
app.get(/^\/error/,  (req, res) => {
	res.redirect('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
});
app.get('/', (req, res) => {
	res.setHeader('content-type', 'text/html; charset=utf-8');
	res.send(`<!doctype html>
		<html lang="de">
			<head>
				<meta charset="utf-8">
				<title>SWUOTA</title>
			</head>
			<body>
				Die Funktion „Geräteverwaltung“ ist beispielsweise erforderlich, um die Firmware über das GPRS-Internet mit dem Telefon selbst zu aktualisieren – „SWUOTA“.<br>
				Wählen Sie zum Konfigurieren auf der Registerkarte „Anwendungen“ die Option „Verwalten“. Gerät“, klicken Sie auf „Ändern“, im erscheinenden Fenster „Profile“ sehen wir eine Liste der Profile.<br>
				Wählen Sie das erste aus und klicken Sie auf „Ändern“. und schreibe die folgenden Daten:<br>
				<br>
				<b>Profilname:</b> Software-Update<br>
				<b>Aufführen. Verbindung:</b> Durch Anklicken öffnet sich das Fenster „Einstellungen“, darin drücken wir „Optionen – Auswählen“. Connect“, das „Netzwerk. Zugriff“, der eine Liste der Profile enthält, die Sie auf der Registerkarte „NAP“ erstellt haben. Wählen Sie „GPRS-Internet“ und speichern Sie unbedingt<br>
				<b>Adresse:</b> http://swuota.global-repair-management.com<br>
				<b>Hafen:</b> 80<br>
				<b>Benutzername:</b> swuota_user<br>
				<b>Passwort:</b> swuota<br>
				<b>Server ID:</b> SWUOTA<br>
				<b>Server passwort:</b> swuota<br>
			</body>
		</html>
	`);
});
app.post('/', (req, res) => {
	let request = fromWBXML(req.body);
	if (!request) {
		res.status(400);
		res.send("Invalid request.");
		return;
	}
	
	let device_id = nodeText(request.SyncML.SyncHdr.Source.LocURI);
	let session_id = +nodeText(request.SyncML.SyncHdr.SessionID);
	
	if (!devices[device_id])
		devices[device_id] = new SwuotaServer(SERVER_AUTH);
	
	let response = devices[device_id].handle(request);
	let wbxml = toWBXML(response);
	let hmac = devices[device_id].getAuthMac(crypto.createHash('md5').update(wbxml).digest());
	
	hmac && res.setHeader('x-syncml-hmac', hmac);
	res.setHeader('Content-Type', 'application/vnd.syncml.dm+wbxml');
	res.send(wbxml);
});

app.listen(9999, () => {
	console.log(`Ololo!`);
});
