const API_BASE = "http://localhost:8080/v1";
let accessToken = "";

function showOutput(data) {
  document.getElementById("output").textContent = JSON.stringify(data, null, 2);
}

async function register() {
  const email = document.getElementById("reg-email").value;
  const password = document.getElementById("reg-password").value;
  const role = document.getElementById("reg-role").value;

  const res = await fetch(`${API_BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, role })
  });

  const data = await res.json();
  showOutput(data);
}

async function login() {
  const email = document.getElementById("login-email").value;
  const password = document.getElementById("login-password").value;

  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();
  if (res.ok && data.accessToken) {
    accessToken = data.accessToken;
  }
  showOutput(data);
}

async function getMe() {
  if (!accessToken) {
    alert("Login first!");
    return;
  }

  const res = await fetch(`${API_BASE}/users/me`, {
    headers: { "Authorization": `Bearer ${accessToken}` }
  });

  const data = await res.json();
  showOutput(data);
}
