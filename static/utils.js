// Copyright (C) 2025 Joshua Goldstein

// Gemini PWD Utility Functions
// Shared functions used across multiple templates

// Constants
const DEFAULT_TAG_COLOR = '#6B7280'; // dark gray - matches backend defaultTagColor

// Authentication and fetch utilities
async function handleAuthResponse(response) {
    // Check for authentication errors
    if (response.status === 401 || response.status === 403) {
        alert('Your session has expired. You will be redirected to the login page.');
        window.location.href = '/logout';
        return null;
    }
    
    // Check if response is HTML (likely a redirect to login page)
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('text/html') && !response.ok) {
        alert('Your session has expired. You will be redirected to the login page.');
        window.location.href = '/logout';
        return null;
    }
    
    return response;
}

async function authFetch(url, options = {}) {
    const timeout = options.timeout || 30000; // Default 30 second timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });
        clearTimeout(timeoutId);
        const authResponse = await handleAuthResponse(response);
        return authResponse;
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            console.error('Request timeout:', url);
            alert('Request timed out. Please check your connection and try again.');
            return null;
        }
        console.error('Fetch error:', error);
        throw error;
    }
}

// Tag color utilities
function getTagColor(color) {
    return color && color.trim() !== '' ? color : DEFAULT_TAG_COLOR;
}

function getTextColor(backgroundColor) {
    // Convert hex to RGB
    const hex = backgroundColor.replace('#', '');
    const r = parseInt(hex.substr(0, 2), 16);
    const g = parseInt(hex.substr(2, 2), 16);
    const b = parseInt(hex.substr(4, 2), 16);
    
    // Calculate brightness using relative luminance formula
    const brightness = (r * 299 + g * 587 + b * 114) / 1000;
    
    // Return black for light colors, white for dark colors
    return brightness > 155 ? '#000000' : '#FFFFFF';
}

function getBorderStyle(backgroundColor) {
    // Convert hex to RGB
    const hex = backgroundColor.replace('#', '');
    const r = parseInt(hex.substr(0, 2), 16);
    const g = parseInt(hex.substr(2, 2), 16);
    const b = parseInt(hex.substr(4, 2), 16);
    
    // Calculate brightness using relative luminance formula
    const brightness = (r * 299 + g * 587 + b * 114) / 1000;
    
    // For very light colors (brightness > 220), use a darker border
    if (brightness > 220) {
        return '2px solid #666666'; // Dark gray border for very light tags
    } else if (brightness > 180) {
        return '1px solid #777777'; // Medium gray border for light tags
    } else {
        return '1px solid #eeeeee'; // Light gray border for darker tags
    }
}

// Tag sorting utility
function sortTagsInContainer(container) {
    const tags = Array.from(container.querySelectorAll('.tag-item'));
    tags.sort((a, b) => {
        const nameA = a.dataset.name.toLowerCase();
        const nameB = b.dataset.name.toLowerCase();
        return nameA.localeCompare(nameB);
    });
    
    // Remove all tags and re-add them in sorted order
    tags.forEach(tag => tag.remove());
    tags.forEach(tag => container.appendChild(tag));
}
