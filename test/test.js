const userInput = req.query.name;
document.body.innerHTML = userInput;

const token = Math.random().toString();

const password = "super-secret-password";