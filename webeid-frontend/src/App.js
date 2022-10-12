import "./App.css";
import { authenticate } from "@web-eid/web-eid-library/dist/es/web-eid.js";
import { useState } from "react";

function App() {
	const [result, setResult] = useState();
	const [disabled, setDisabled] = useState();

	async function handleAuth() {
		setDisabled(true);

		try {
			const challengeResponse = await fetch(
				"http://localhost:3001/auth/challenge",
				{
					method: "GET",
					headers: JSON.parse('{ "X-Nonce-Length": "44" }' || "{}"),
				}
			);

			const { challengeNonce } = await challengeResponse.json();

			const authToken = await authenticate(challengeNonce, {
				lang: "et",
				userInteractionTimeout: 120000,
			});

			const authTokenResponse = await fetch(
				"http://localhost:3001/auth/token",
				{
					method: "POST",
					headers: JSON.parse('{ "Content-Type": "application/json" }' || "{}"),
					body: JSON.stringify(authToken),
				}
			);

			const authTokenResult = await authTokenResponse.json();

			setResult(authTokenResult);
		} catch (error) {
			setResult(undefined);

			console.error(error);

			throw error;
		} finally {
			setDisabled(false);
		}
	}

	return (
		<div className="app">
			<p>
				<button disabled={disabled} className="btn" onClick={handleAuth}>
					Autendi
				</button>
			</p>
			{result && (
				<h2>
					Tere tulemast, {result.subject.GN} {result.subject.SN}!
				</h2>
			)}
		</div>
	);
}

export default App;
