/**
 * Clipboard functionality for copying values with visual feedback
 */

/**
 * Copy text to clipboard with visual feedback on the button
 * @param {string} text - The text to copy
 * @param {HTMLElement} buttonElement - The button element to show feedback on
 */
function copyToClipboard(text, buttonElement) {
    const originalText = buttonElement.textContent;

    // Try modern clipboard API first
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text)
            .then(function() {
                showCopySuccess(buttonElement, originalText);
            })
            .catch(function() {
                // Fallback if clipboard API fails (e.g., permissions)
                fallbackCopy(text, buttonElement, originalText);
            });
    } else {
        // Fallback for older browsers
        fallbackCopy(text, buttonElement, originalText);
    }
}

/**
 * Fallback copy method using textarea and execCommand
 * @param {string} text - The text to copy
 * @param {HTMLElement} buttonElement - The button element to show feedback on
 * @param {string} originalText - Original button text for reset
 */
function fallbackCopy(text, buttonElement, originalText) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    textarea.style.top = '0';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();

    try {
        var successful = document.execCommand('copy');
        if (successful) {
            showCopySuccess(buttonElement, originalText);
        } else {
            showCopyError(buttonElement, originalText);
        }
    } catch (err) {
        showCopyError(buttonElement, originalText);
    }

    document.body.removeChild(textarea);
}

/**
 * Show success feedback on button
 * @param {HTMLElement} buttonElement - The button element
 * @param {string} originalText - Original button text for reset
 */
function showCopySuccess(buttonElement, originalText) {
    buttonElement.textContent = 'Copied!';
    buttonElement.classList.add('copy-success');

    setTimeout(function() {
        buttonElement.textContent = originalText;
        buttonElement.classList.remove('copy-success');
    }, 2000);
}

/**
 * Show error feedback on button
 * @param {HTMLElement} buttonElement - The button element
 * @param {string} originalText - Original button text for reset
 */
function showCopyError(buttonElement, originalText) {
    buttonElement.textContent = 'Failed';
    buttonElement.classList.add('copy-error');

    setTimeout(function() {
        buttonElement.textContent = originalText;
        buttonElement.classList.remove('copy-error');
    }, 2000);
}

/**
 * Initialize copy buttons on page load
 * Buttons should have data-copy-target attribute pointing to element ID
 * Example: <button data-copy-target="webhook-url">Copy</button>
 */
function initClipboardButtons() {
    var copyButtons = document.querySelectorAll('[data-copy-target]');

    copyButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            var targetId = this.getAttribute('data-copy-target');
            var targetElement = document.getElementById(targetId);

            if (targetElement) {
                // Handle both input elements and regular elements
                var textToCopy = targetElement.value !== undefined
                    ? targetElement.value
                    : targetElement.textContent;
                copyToClipboard(textToCopy, this);
            }
        });
    });
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', initClipboardButtons);
