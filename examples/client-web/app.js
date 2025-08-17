const API_BASE = "http://localhost:8080/v1";
let accessToken = "";

function showOutput(data) {
  document.getElementById("output").textContent = JSON.stringify(data, null, 2);
}

function setToken(token) {
  accessToken = token || accessToken;
  const badge = document.getElementById("token-status");
  if (accessToken) { badge.textContent = "Token: OK"; badge.style.color = "green"; }
  else { badge.textContent = "Token: none"; badge.style.color = "red"; }
}

function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randDigits(n) { let s=""; for (let i=0;i<n;i++) s += String(randInt(0,9)); return s; }
function randEmail() { return `user_${randDigits(6)}@example.com`; }
function randPhoneBR() { return `55${randDigits(2)}9${randDigits(8)}`; }
function randCPF() { return randDigits(11); }
function randCNPJ() { return randDigits(14); }
function randUsername() { return `user_${randDigits(6)}`; }
function randDOB() { const y=randInt(1970,2005), m=randInt(1,12), d=randInt(1,28); return `${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`; }
function randProvider() { return ["google","apple"][randInt(0,1)]; }
function randProviderUser() { return `prov_${randDigits(10)}`; }

// Buttons: fill random
function fillRegisterRandom() {
  document.getElementById("reg-email").value = randEmail();
  document.getElementById("reg-password").value = "Secret123!";
  document.getElementById("reg-role").value = "customer";
  document.getElementById("reg-phone").value = randPhoneBR();
  document.getElementById("reg-username").value = randUsername();
  document.getElementById("reg-cpf").value = randCPF();
  document.getElementById("reg-cnpj").value = randCNPJ();
  document.getElementById("reg-dob").value = randDOB();
}
function fillRegisterOAuthRandom() {
  fillRegisterRandom();
  document.getElementById("reg-prov").value = randProvider();
  document.getElementById("reg-prov-user").value = randProviderUser();
}
function fillLoginRandom() {
  // choose a strategy randomly
  const strategies = [
    () => ({ email: randEmail(), password: "Secret123!" }),
    () => ({ phone_number: randPhoneBR(), password: "Secret123!" }),
    () => ({ username: randUsername(), password: "Secret123!" }),
    () => ({ cpf: randCPF(), password: "Secret123!" }),
    () => ({ cnpj: randCNPJ(), password: "Secret123!" }),
    () => ({ email: randEmail() }),
    () => ({ phone_number: randPhoneBR() }),
    () => ({ username: randUsername() }),
    () => ({ cpf: randCPF() }),
    () => ({ cnpj: randCNPJ() }),
    () => ({ email: randEmail(), date_of_birth: randDOB() }),
    () => ({ phone_number: randPhoneBR(), date_of_birth: randDOB() }),
  ];
  const chosen = strategies[randInt(0, strategies.length-1)]();
  document.getElementById("login-email").value = chosen.email || "";
  document.getElementById("login-password").value = chosen.password || "";
  document.getElementById("login-phone").value = chosen.phone_number || "";
  document.getElementById("login-username").value = chosen.username || "";
  document.getElementById("login-cpf").value = chosen.cpf || "";
  document.getElementById("login-cnpj").value = chosen.cnpj || "";
  document.getElementById("login-dob").value = chosen.date_of_birth || "";
}
function fillOAuthLoginRandom() {
  document.getElementById("oauth-prov").value = randProvider();
  document.getElementById("oauth-prov-user").value = randProviderUser();
}

// Calls
async function register() {
  const payload = {
    email: document.getElementById("reg-email").value,
    password: document.getElementById("reg-password").value,
    role: document.getElementById("reg-role").value,
    phone_number: document.getElementById("reg-phone").value,
    username: document.getElementById("reg-username").value,
    cpf: document.getElementById("reg-cpf").value,
    cnpj: document.getElementById("reg-cnpj").value,
    date_of_birth: document.getElementById("reg-dob").value,
  };
  const res = await fetch(`${API_BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  showOutput(data);
}

async function registerOAuth() {
  const payload = {
    email: document.getElementById("reg-email").value,
    role: document.getElementById("reg-role").value,
    phone_number: document.getElementById("reg-phone").value,
    username: document.getElementById("reg-username").value,
    cpf: document.getElementById("reg-cpf").value,
    cnpj: document.getElementById("reg-cnpj").value,
    date_of_birth: document.getElementById("reg-dob").value,
    provider: document.getElementById("reg-prov").value,
    provider_user_id: document.getElementById("reg-prov-user").value,
  };
  const res = await fetch(`${API_BASE}/auth/register/oauth`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  showOutput(data);
}

async function login() {
  const payload = {
    email: document.getElementById("login-email").value,
    password: document.getElementById("login-password").value,
    phone_number: document.getElementById("login-phone").value,
    username: document.getElementById("login-username").value,
    cpf: document.getElementById("login-cpf").value,
    cnpj: document.getElementById("login-cnpj").value,
    date_of_birth: document.getElementById("login-dob").value,
  };
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  if (res.ok && data.accessToken) {
    setToken(data.accessToken);
  }
  showOutput(data);
}

async function loginOAuth() {
  const payload = {
    provider: document.getElementById("oauth-prov").value,
    provider_user_id: document.getElementById("oauth-prov-user").value,
  };
  const res = await fetch(`${API_BASE}/auth/login/oauth`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  if (res.ok && data.accessToken) {
    setToken(data.accessToken);
  }
  showOutput(data);
}

async function getMe() {
  if (!accessToken) { alert("Login first!"); return; }
  const res = await fetch(`${API_BASE}/users/me`, { headers: { "Authorization": `Bearer ${accessToken}` } });
  const data = await res.json();
  showOutput(data);
}

// Debug viewers
async function viewLoginConfigs() { const res = await fetch(`${API_BASE}/debug/login-configs`); const data = await res.json(); showOutput(data); }
async function viewRegisterConfigs() { const res = await fetch(`${API_BASE}/debug/register-configs`); const data = await res.json(); showOutput(data); }
async function viewOAuthProviders() { const res = await fetch(`${API_BASE}/debug/oauth-providers`); const data = await res.json(); showOutput(data); }
async function viewUsers() { const res = await fetch(`${API_BASE}/debug/users`); const data = await res.json(); showOutput(data); }
async function viewRoles() { const res = await fetch(`${API_BASE}/debug/roles`); const data = await res.json(); showOutput(data); }
async function viewUserRoles() { const res = await fetch(`${API_BASE}/debug/user-roles`); const data = await res.json(); showOutput(data); }

window.fillRegisterRandom = fillRegisterRandom;
window.fillRegisterOAuthRandom = fillRegisterOAuthRandom;
window.fillLoginRandom = fillLoginRandom;
window.fillOAuthLoginRandom = fillOAuthLoginRandom;
window.register = register;
window.registerOAuth = registerOAuth;
window.login = login;
window.loginOAuth = loginOAuth;
window.getMe = getMe;
window.viewLoginConfigs = viewLoginConfigs;
window.viewRegisterConfigs = viewRegisterConfigs;
window.viewOAuthProviders = viewOAuthProviders;
window.viewUsers = viewUsers;
window.viewRoles = viewRoles;
window.viewUserRoles = viewUserRoles;
