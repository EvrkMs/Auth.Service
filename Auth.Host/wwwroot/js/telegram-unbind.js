(() => {
    const form = document.getElementById('unbind-form');
    const passwordInput = form?.querySelector('input[name="Password"]');
    const validationSpan = form?.querySelector('[data-valmsg-for="Password"]');

    form?.addEventListener('submit', (event) => {
        if (passwordInput && passwordInput.value.trim().length === 0) {
            if (validationSpan) {
                validationSpan.textContent = 'Пароль обязателен';
            }
            event.preventDefault();
        }
    });
})();
