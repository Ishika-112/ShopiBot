document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector("form");
    const username = document.querySelector("#username");
    const email = document.querySelector("#email");
    const password = document.querySelector("#password");
    const confirmPassword = document.querySelector("#confirm_password");
   

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    form.addEventListener("submit", function (e) {
        if (!emailPattern.test(email.value.trim())) {
            alert("Please enter a valid email address.");
            e.preventDefault();
            return;
        }

        if (password.value.length < 8) {
            alert("Password must be at least 8 characters.");
            e.preventDefault();
            return;
        }

        if (password.value !== confirmPassword.value) {
            alert("Passwords do not match.");
            e.preventDefault();
            return;
        }

    
    });

   
    const msg = document.querySelector("#message");
    if (msg && msg.textContent.trim()) {
        alert(msg.textContent.trim());
    }
});

