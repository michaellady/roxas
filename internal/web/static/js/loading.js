/**
 * Loading states for async operations
 * Provides visual feedback when forms are submitted or async actions occur
 */

/**
 * Add loading state to a button
 * @param {HTMLElement} button - The button element
 */
function setButtonLoading(button) {
    if (!button || button.classList.contains('loading')) return;

    button.classList.add('loading');
    button.disabled = true;
    button.setAttribute('data-original-text', button.textContent);
}

/**
 * Remove loading state from a button
 * @param {HTMLElement} button - The button element
 */
function clearButtonLoading(button) {
    if (!button) return;

    button.classList.remove('loading');
    button.disabled = false;

    var originalText = button.getAttribute('data-original-text');
    if (originalText) {
        button.textContent = originalText;
        button.removeAttribute('data-original-text');
    }
}

/**
 * Initialize form loading states
 * Automatically adds loading state to submit buttons when forms are submitted
 */
function initFormLoadingStates() {
    document.addEventListener('submit', function(e) {
        var form = e.target;
        if (!form || form.tagName !== 'FORM') return;

        // Skip forms with data-no-loading attribute
        if (form.hasAttribute('data-no-loading')) return;

        // Find submit button(s) in the form
        var submitButtons = form.querySelectorAll('button[type="submit"], input[type="submit"]');

        submitButtons.forEach(function(button) {
            setButtonLoading(button);
        });

        // Also handle the button that was clicked (in case it's outside the form)
        var activeElement = document.activeElement;
        if (activeElement &&
            (activeElement.tagName === 'BUTTON' || activeElement.tagName === 'INPUT') &&
            activeElement.type === 'submit') {
            setButtonLoading(activeElement);
        }
    });
}

/**
 * Initialize click loading states for buttons/links with data-loading attribute
 * Example: <button data-loading>Click me</button>
 * Example: <a href="/action" data-loading>Do action</a>
 */
function initClickLoadingStates() {
    document.addEventListener('click', function(e) {
        var target = e.target.closest('[data-loading]');
        if (!target) return;

        // For links, add loading state immediately
        if (target.tagName === 'A') {
            setButtonLoading(target);
        }

        // For buttons not in forms (or non-submit buttons), add loading state
        if (target.tagName === 'BUTTON' && target.type !== 'submit') {
            setButtonLoading(target);
        }
    });
}

/**
 * Show a loading overlay on a container
 * @param {HTMLElement} container - The container element
 * @param {string} message - Optional loading message
 */
function showLoadingOverlay(container, message) {
    if (!container) return;

    // Check if overlay already exists
    if (container.querySelector('.loading-overlay')) return;

    var overlay = document.createElement('div');
    overlay.className = 'loading-overlay';
    overlay.innerHTML = '<div class="loading-overlay-content">' +
        '<span class="spinner"></span>' +
        (message ? '<span class="loading-message">' + message + '</span>' : '') +
        '</div>';

    container.style.position = 'relative';
    container.appendChild(overlay);
}

/**
 * Hide loading overlay from a container
 * @param {HTMLElement} container - The container element
 */
function hideLoadingOverlay(container) {
    if (!container) return;

    var overlay = container.querySelector('.loading-overlay');
    if (overlay) {
        overlay.remove();
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    initFormLoadingStates();
    initClickLoadingStates();
});
