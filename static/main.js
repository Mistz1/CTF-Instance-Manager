/* static/main.js */

function startChallenge() {
    const inputField = document.getElementById('challengeInput');
    const challengeName = inputField.value.trim();
    
    if (challengeName) {
        // Optional: Add loading state to button
        const btn = document.querySelector('button[onclick="startChallenge()"]');
        if(btn) {
            btn.innerHTML = 'DEPLOYING...';
            btn.classList.add('opacity-75', 'cursor-not-allowed');
        }

        // Redirect
        window.location.href = `/start/${challengeName}`;
    } else {
        // Shake animation for error
        inputField.classList.add('border-red-800');
        setTimeout(() => {
            inputField.classList.remove('border-red-800');
        }, 500);
    }
}

// Allow pressing "Enter" to submit
document.addEventListener("DOMContentLoaded", function() {
    const input = document.getElementById("challengeInput");
    if (input) {
        input.addEventListener("keypress", function(event) {
            if (event.key === "Enter") {
                event.preventDefault();
                startChallenge();
            }
        });
    }
});