// public/login.js

document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("login-form");

    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        const username = document.getElementById("username").value.trim();
        const password = document.getElementById("password").value.trim();

        if (!username || !password) {
            alert("Please fill in all fields.");
            return;
        }

        try {
            const response = await fetch("/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();
            if (response.ok && data.token) {
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
});
