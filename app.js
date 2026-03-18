// public/app.js

document.addEventListener("DOMContentLoaded", () => {
    // Register form submission
    document.getElementById("register-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        
        const username = document.getElementById("register-username").value;
        const password = document.getElementById("register-password").value;
        
        const response = await fetch("http://localhost:3000/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();
        if (response.ok) {
            alert("Registration successful!");
            window.location.href = "index.html"; // Redirect to login page
        } else {
            alert(data.message);
        }
    });

    // Login form submission
    document.getElementById("login-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;

        const response = await fetch("http://localhost:3000/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();
        if (response.ok) {
            localStorage.setItem("token", data.token); // Store token
            window.location.href = "dashboard.html";  // Redirect to dashboard
        } else {
            alert(data.message);
        }
    });
});