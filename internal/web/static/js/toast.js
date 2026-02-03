/**
 * Toast Notification System
 * Provides non-blocking, auto-dismissing notifications for user feedback
 */

(function() {
    'use strict';

    // Configuration
    var DEFAULT_DURATION = 5000; // 5 seconds
    var ANIMATION_DURATION = 300; // CSS transition duration in ms

    // Toast container element
    var container = null;

    /**
     * Initialize the toast container
     */
    function initContainer() {
        if (container) return container;

        container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        return container;
    }

    /**
     * Show a toast notification
     * @param {string} message - The message to display
     * @param {string} type - Toast type: 'success', 'error', 'warning', 'info'
     * @param {number} duration - Duration in ms before auto-dismiss (0 for no auto-dismiss)
     */
    function showToast(message, type, duration) {
        type = type || 'info';
        duration = duration !== undefined ? duration : DEFAULT_DURATION;

        initContainer();

        // Create toast element
        var toast = document.createElement('div');
        toast.className = 'toast toast-' + type;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'polite');

        // Toast content
        var content = document.createElement('div');
        content.className = 'toast-content';

        // Icon based on type
        var icon = document.createElement('span');
        icon.className = 'toast-icon';
        icon.innerHTML = getIconForType(type);

        // Message text
        var text = document.createElement('span');
        text.className = 'toast-message';
        text.textContent = message;

        // Close button
        var closeBtn = document.createElement('button');
        closeBtn.className = 'toast-close';
        closeBtn.innerHTML = '&times;';
        closeBtn.setAttribute('aria-label', 'Close');
        closeBtn.onclick = function() {
            dismissToast(toast);
        };

        content.appendChild(icon);
        content.appendChild(text);
        content.appendChild(closeBtn);
        toast.appendChild(content);

        // Progress bar for auto-dismiss
        if (duration > 0) {
            var progress = document.createElement('div');
            progress.className = 'toast-progress';
            var progressBar = document.createElement('div');
            progressBar.className = 'toast-progress-bar';
            progressBar.style.animationDuration = duration + 'ms';
            progress.appendChild(progressBar);
            toast.appendChild(progress);
        }

        // Add to container
        container.appendChild(toast);

        // Trigger animation
        requestAnimationFrame(function() {
            toast.classList.add('toast-visible');
        });

        // Auto-dismiss
        if (duration > 0) {
            setTimeout(function() {
                dismissToast(toast);
            }, duration);
        }

        return toast;
    }

    /**
     * Dismiss a toast
     * @param {HTMLElement} toast - The toast element to dismiss
     */
    function dismissToast(toast) {
        if (!toast || toast.classList.contains('toast-dismissing')) return;

        toast.classList.add('toast-dismissing');
        toast.classList.remove('toast-visible');

        setTimeout(function() {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, ANIMATION_DURATION);
    }

    /**
     * Get icon HTML for toast type
     * @param {string} type - Toast type
     * @returns {string} Icon HTML
     */
    function getIconForType(type) {
        switch (type) {
            case 'success':
                return '&#x2713;'; // Checkmark
            case 'error':
                return '&#x2717;'; // X mark
            case 'warning':
                return '&#x26A0;'; // Warning triangle
            case 'info':
            default:
                return '&#x2139;'; // Info circle
        }
    }

    /**
     * Parse URL query parameters for flash messages
     * Supports: ?error=message, ?success=message, ?warning=message, ?info=message
     * Also supports legacy: ?disconnected=platform
     */
    function parseQueryParamFlash() {
        var params = new URLSearchParams(window.location.search);
        var shown = false;

        // Check for typed messages
        var types = ['error', 'success', 'warning', 'info'];
        types.forEach(function(type) {
            var message = params.get(type);
            if (message) {
                showToast(decodeURIComponent(message), type);
                shown = true;
            }
        });

        // Legacy: ?disconnected=platform
        var disconnected = params.get('disconnected');
        if (disconnected) {
            showToast('Successfully disconnected from ' + disconnected, 'success');
            shown = true;
        }

        // Legacy: ?connected=platform
        var connected = params.get('connected');
        if (connected) {
            showToast('Successfully connected to ' + connected, 'success');
            shown = true;
        }

        // Clean up URL if we showed a toast
        if (shown && window.history && window.history.replaceState) {
            var cleanUrl = window.location.pathname;
            // Preserve non-flash params
            var preservedParams = new URLSearchParams();
            params.forEach(function(value, key) {
                if (types.indexOf(key) === -1 && key !== 'disconnected' && key !== 'connected') {
                    preservedParams.set(key, value);
                }
            });
            if (preservedParams.toString()) {
                cleanUrl += '?' + preservedParams.toString();
            }
            window.history.replaceState({}, document.title, cleanUrl);
        }
    }

    /**
     * Convert existing flash message div to toast
     */
    function convertFlashToToast() {
        var flashAlert = document.querySelector('.alert[data-flash]');
        if (flashAlert) {
            var message = flashAlert.textContent.trim();
            var type = 'info';

            if (flashAlert.classList.contains('alert-success')) {
                type = 'success';
            } else if (flashAlert.classList.contains('alert-error')) {
                type = 'error';
            } else if (flashAlert.classList.contains('alert-warning')) {
                type = 'warning';
            }

            // Hide original and show toast
            flashAlert.style.display = 'none';
            showToast(message, type);
        }
    }

    // Initialize on DOM ready
    document.addEventListener('DOMContentLoaded', function() {
        initContainer();
        parseQueryParamFlash();
        convertFlashToToast();
    });

    // Expose API globally
    window.Toast = {
        show: showToast,
        success: function(message, duration) {
            return showToast(message, 'success', duration);
        },
        error: function(message, duration) {
            return showToast(message, 'error', duration);
        },
        warning: function(message, duration) {
            return showToast(message, 'warning', duration);
        },
        info: function(message, duration) {
            return showToast(message, 'info', duration);
        },
        dismiss: dismissToast
    };
})();
