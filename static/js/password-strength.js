function setupPasswordStrengthChecker(
    passwordInputId, 
    strengthBarId, 
    feedbackId, 
    confirmInputId = null, 
    matchFeedbackId = null
) {
    const passwordInput = document.getElementById(passwordInputId);
    const strengthBar = document.getElementById(strengthBarId);
    const feedback = document.getElementById(feedbackId);
    const confirmInput = confirmInputId ? document.getElementById(confirmInputId) : null;
    const matchFeedback = matchFeedbackId ? document.getElementById(matchFeedbackId) : null;
    
    // Check password strength
    passwordInput.addEventListener('input', async function() {
        const password = this.value;
        
        if (password.length === 0) {
            strengthBar.style.width = '0%';
            strengthBar.className = 'progress-bar';
            feedback.innerHTML = '';
            return;
        }
        
        try {
            const response = await fetch(`/dashboard/check-password-strength?password=${encodeURIComponent(password)}`);
            const data = await response.json();
            
            // Update strength bar
            strengthBar.style.width = `${data.score}%`;
            
            if (data.score >= 80) {
                strengthBar.className = 'progress-bar bg-success';
            } else if (data.score >= 50) {
                strengthBar.className = 'progress-bar bg-warning';
            } else {
                strengthBar.className = 'progress-bar bg-danger';
            }
            
            // Update feedback
            let feedbackHtml = '';
            
            if (data.issues.length > 0) {
                feedbackHtml += '<ul class="mt-2 mb-0 ps-3">';
                data.issues.forEach(issue => {
                    feedbackHtml += `<li class="text-danger small">${issue}</li>`;
                });
                feedbackHtml += '</ul>';
            }
            
            if (data.has_been_breached) {
                feedbackHtml += `<div class="text-danger small mt-2">⚠️ This password has been found in ${data.breach_count} data breaches!</div>`;
            }
            
            if (data.is_common) {
                feedbackHtml += '<div class="text-danger small mt-2">⚠️ This is a commonly used password!</div>';
            }
            
            if (data.score >= 80 && !data.has_been_breached && !data.is_common && data.issues.length === 0) {
                feedbackHtml = '<div class="text-success small mt-2">Strong password!</div>';
            }
            
            feedback.innerHTML = feedbackHtml;
        } catch (error) {
            console.error('Error checking password strength:', error);
        }
    });
    
    // Check password match if confirm input exists
    if (confirmInput && matchFeedback) {
        confirmInput.addEventListener('input', function() {
            const password = passwordInput.value;
            const confirm = this.value;
            
            if (confirm.length === 0) {
                matchFeedback.innerHTML = '';
                return;
            }
            
            if (password === confirm) {
                matchFeedback.innerHTML = '<div class="text-success small mt-2">Passwords match!</div>';
            } else {
                matchFeedback.innerHTML = '<div class="text-danger small mt-2">Passwords do not match!</div>';
            }
        });
    }
}