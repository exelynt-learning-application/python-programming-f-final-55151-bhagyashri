// public/app.js

document.addEventListener("DOMContentLoaded", () => {
    const registerForm = document.getElementById("register-form");
    const loginForm = document.getElementById("login-form");

    // Register form submission (only on register.html)
    if (registerForm) {
        registerForm.addEventListener("submit", async (e) => {
            e.preventDefault();

            const username = document.getElementById("register-username").value;
            const password = document.getElementById("register-password").value;

            try {
                const response = await fetch("/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();
                if (response.ok) {
                    alert("Registration successful!");
                    window.location.href = "index.html";
                } else {
                    const errorMsg = data.errors
                        ? data.errors.map(err => err.msg).join("\n")
                        : data.message;
                    alert(errorMsg);
                }
            } catch (error) {
                alert("An error occurred. Please try again.");
            }
        });
    }

    // Login form submission (only on index.html)
    if (loginForm) {
        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();

            const username = document.getElementById("username").value;
            const password = document.getElementById("password").value;

            try {
                const response = await fetch("/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();
                if (response.ok && data.token) {
                    // Validate token format before storing (JWT has 3 dot-separated parts)
                    const parts = data.token.split(".");
                    if (parts.length !== 3) {
                        alert("Received invalid token from server.");
                        return;
                    }
                    sessionStorage.setItem("token", data.token);
                    window.location.href = "dashboard.html";
                } else {
                    const errorMsg = data.errors
                        ? data.errors.map(err => err.msg).join("\n")
                        : data.message;
                    alert(errorMsg);
                }
            } catch (error) {
                alert("An error occurred. Please try again.");
            }
        });
    }
});
