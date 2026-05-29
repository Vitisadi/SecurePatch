import { exec } from "child_process";

const userInput = String(req.query.name);

document.body.innerHTML = userInput;

const resetToken = Math.random().toString(36);

const api_key = "test-api-key-123456789";

const query = `SELECT * FROM accounts WHERE email = ${userInput}`;

exec("git log --author=" + userInput);
