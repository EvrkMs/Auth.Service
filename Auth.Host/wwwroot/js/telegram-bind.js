(() => {
    const form = document.querySelector('form');
    const statusEl = document.getElementById('status');
    const bindButton = document.getElementById('bind-button');
    const passwordInput = document.getElementById('password-input');
    const tgStatusIcon = document.getElementById('tg-status-icon');
    const widgetErrorEl = document.getElementById('widget-error');
    const scriptEl = document.currentScript;

    const safeReturnUrl = scriptEl?.dataset?.safeReturnUrl || '/';
    const shouldLog = scriptEl?.dataset?.dev === 'true';
    const botUsername = scriptEl?.dataset?.botUsername || '';
    const csrfToken = form?.querySelector('input[name="__RequestVerificationToken"]')?.value;

    let telegramUser = null;
    let telegramConfirmed = false;
    let widgetTimeoutId = null;

    if (widgetErrorEl && !widgetErrorEl.getAttribute('data-default-html')) {
        widgetErrorEl.setAttribute('data-default-html', widgetErrorEl.innerHTML);
    }

    function setStatus(message, isError = false) {
        if (!statusEl) return;
        statusEl.textContent = message;
        statusEl.classList.toggle('error', isError);
    }

    function showWidgetError(message) {
        if (!widgetErrorEl) return;
        widgetErrorEl.style.display = 'block';
        const defaultHtml = widgetErrorEl.getAttribute('data-default-html');
        widgetErrorEl.innerHTML = defaultHtml || message;
        if (!defaultHtml) {
            widgetErrorEl.textContent = message;
        }
    }

    function updateBindButtonState() {
        const hasPassword = passwordInput && passwordInput.value.trim().length > 0;
        bindButton.disabled = !(telegramConfirmed && hasPassword);
    }

    function handleTelegramAuth(user) {
        if (shouldLog) {
            console.log('handleTelegramAuth user:', user);
        } else {
            console.debug && console.debug('handleTelegramAuth user:', user);
        }
        telegramUser = user;
        telegramConfirmed = true;

        const label = user.username ? '@' + user.username : user.first_name || 'Telegram пользователь';
        setStatus(`Подтверждён аккаунт ${label}. Теперь можно привязать.`, false);

        if (tgStatusIcon) {
            tgStatusIcon.classList.add('success');
        }

        updateBindButtonState();
    }

    window.handleTelegramAuth = handleTelegramAuth;

    window.handleTelegramWidgetLoaded = function () {
        window.__telegramWidgetLoaded = true;
    };

    window.handleTelegramWidgetError = function () {
        window.__telegramWidgetError = true;
    };

    if (Array.isArray(window.__telegramQueue) && window.__telegramQueue.length > 0) {
        window.__telegramQueue.forEach((user) => handleTelegramAuth(user));
        window.__telegramQueue = [];
    }

    function scheduleWidgetTimeout() {
        if (widgetTimeoutId) {
            clearTimeout(widgetTimeoutId);
        }
        widgetTimeoutId = setTimeout(() => {
            if (telegramConfirmed) return;
            if (window.__telegramWidgetLoaded) return;
            showWidgetError('Виджет Telegram не загрузился. Откройте бота напрямую или отключите блокировщики.');
            setStatus('Виджет Telegram не загрузился. Попробуйте еще раз или откройте бота напрямую.', true);
        }, 15000);
    }

    if (typeof window !== 'undefined') {
        scheduleWidgetTimeout();
    }

    if (passwordInput) {
        passwordInput.addEventListener('input', () => {
            setStatus(
                telegramConfirmed
                    ? 'Telegram подтверждён. Можно привязать аккаунт.'
                    : 'Telegram пока не подтверждён.',
                false
            );
            updateBindButtonState();
        });
    }

    async function submitTelegramBind(event) {
        event.preventDefault();

        if (!telegramUser) {
            setStatus('Сначала подтвердите вход через Telegram.', true);
            return;
        }

        const password = passwordInput.value.trim();
        if (!password) {
            setStatus('Введите пароль для подтверждения.', true);
            return;
        }

        bindButton.disabled = true;
        setStatus('Выполняем привязку...', false);

        try {
            const payload = {
                id: telegramUser.id,
                firstName: telegramUser.first_name,
                lastName: telegramUser.last_name,
                username: telegramUser.username,
                photoUrl: telegramUser.photo_url,
                authDate: telegramUser.auth_date,
                hash: telegramUser.hash,
                password
            };

            if (shouldLog) {
                console.log('Submitting payload:', payload);
            }

            const headers = { 'Content-Type': 'application/json' };
            if (csrfToken) {
                headers['X-CSRF-TOKEN'] = csrfToken;
            }

            const response = await fetch('/api/telegram/bind', {
                method: 'POST',
                headers,
                credentials: 'include',
                body: JSON.stringify(payload)
            });

            if (shouldLog) {
                console.log('Response status:', response.status);
            }

            if (!response.ok) {
                const text = await response.text();
                let error = {};
                try {
                    error = JSON.parse(text);
                } catch { }

                throw new Error(error.detail || 'Не удалось привязать Telegram');
            }

            window.location.href = safeReturnUrl;
        } catch (error) {
            console.error('Bind error:', error);
            setStatus(error.message || 'Произошла ошибка', true);
        } finally {
            updateBindButtonState();
        }
    }

    if (form) {
        form.addEventListener('submit', submitTelegramBind);
    }

    // inject widget script with dynamic botUsername
    if (botUsername) {
        const widgetContainer = document.getElementById('telegram-widget');
        if (widgetContainer) {
            const script = document.createElement('script');
            script.dataset.cfasync = 'false';
            script.async = true;
            script.src = 'https://telegram.org/js/telegram-widget.js?22';
            script.setAttribute('data-telegram-login', botUsername);
            script.setAttribute('data-size', 'large');
            script.setAttribute('data-request-access', 'write');
            script.setAttribute('data-onauth', 'handleTelegramAuth(user)');
            script.onload = window.handleTelegramWidgetLoaded;
            script.onerror = window.handleTelegramWidgetError;
            widgetContainer.appendChild(script);
        }
    }
})();
