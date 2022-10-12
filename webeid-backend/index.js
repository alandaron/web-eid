const http = require("http");
const path = require("path");
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const session = require("express-session");

const app = express();

const oneDay = 1000 * 60 * 60 * 24;

let tls = require("tls");
let net = require("net");

app.use(
	cors({
		credentials: true,
		origin: "*",
	})
);
app.use(
	"*",
	session({
		name: "session",
		secret: "secret",
		resave: false,
		saveUninitialized: true,

		cookie: {
			sameSite: "none", // Needed for CORS
			secure: true,
			httpOnly: true,
			maxAge: oneDay,
		},
	})
);

if (!process.argv.slice(2).includes("--no-csp")) {
	app.use(helmet.contentSecurityPolicy());
}
app.use(helmet.dnsPrefetchControl());
app.use(helmet.expectCt());
app.use(helmet.frameguard());
app.use(helmet.hidePoweredBy());
app.use(helmet.hsts());
app.use(helmet.ieNoOpen());
app.use(helmet.noSniff());
app.use(helmet.permittedCrossDomainPolicies());
app.use(helmet.referrerPolicy());
app.use(helmet.xssFilter());

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.get("/auth/challenge", (req, res) => {
	const nonceLength = req.header("X-Nonce-Length")
		? parseInt(req.header("X-Nonce-Length"), 10)
		: 32;

	// String of random numbers from 0-9 with the string length of nonceLength
	// For example if nonceLength is 5, nonce could be "77391"
	const challengeNonce = Array.from(
		{ length: nonceLength },
		() => "" + Math.floor(Math.random() * 10)
	).join("");

	res.set("Content-Type", "application/json");
	res.send({ challengeNonce });
});

app.post("/auth/token", (req, res) => {
	const required = [
		"algorithm",
		"appVersion",
		"format",
		"signature",
		"unverifiedCertificate",
	];

	if (required.every((key) => !!req.body[key])) {
		// Võtame sertifikaadi seest välja isiku andmed.
		// [TODO]: Tuleks kindlasti sertifikaadi autentsust kontrollida!

		let secureContext = tls.createSecureContext({
			cert: `-----BEGIN CERTIFICATE-----\n${req.body["unverifiedCertificate"]}\n-----END CERTIFICATE-----`,
		});

		let secureSocket = new tls.TLSSocket(new net.Socket(), { secureContext });
		let cert = secureSocket.getCertificate();
		secureSocket.destroy();

		res.send({
			authenticated: true,
			subject: cert.subject,
			authTokenWas: req.body,
		});
	} else {
		res.status(401).send({ authenticated: false, authTokenWas: req.body });
	}
});

/**
 * Get port from environment and store in Express.
 */
const port = normalizePort(process.env.PORT || "3001");
app.set("port", port);

/**
 * Create HTTP server.
 */
const server = http.createServer(app);

/**
 * Listen on provided port, on all network interfaces.
 */
server.listen(port);
server.on("error", onError);
server.on("listening", onListening);

/**
 * Normalize a port into a number, string, or false.
 */
function normalizePort(val) {
	const port = parseInt(val, 10);

	if (isNaN(port)) {
		// named pipe
		return val;
	}

	if (port >= 0) {
		// port number
		return port;
	}

	return false;
}

/**
 * Event listener for HTTP server "error" event.
 */
function onError(error) {
	if (error.syscall !== "listen") {
		throw error;
	}

	const bind = typeof port === "string" ? "Pipe " + port : "Port " + port;

	// handle specific listen errors with friendly messages
	switch (error.code) {
		case "EACCES":
			console.error(bind + " requires elevated privileges");
			process.exit(1);

		case "EADDRINUSE":
			console.error(bind + " is already in use");
			process.exit(1);

		default:
			throw error;
	}
}

/**
 * Event listener for HTTP server "listening" event.
 */
function onListening() {
	const addr = server.address();
	const bind = typeof addr === "string" ? "pipe " + addr : "port " + addr.port;
	console.log("Listening on " + bind);
}
