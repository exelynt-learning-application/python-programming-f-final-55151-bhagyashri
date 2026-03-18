// public/register.js

document.addEventListener("DOMContentLoaded", () => {
    const registerForm = document.getElementById("register-form");

    registerForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        const username = document.getElementById("register-username").value.trim();
        const password = document.getElementById("register-password").value.trim();

        if (!username || !password) {
            alert("Please fill in all fields.");
            return;
        }

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
});
