/**
 * Device Fingerprint Collector
 * Collects browser-accessible device signals for enhanced device identification
 */

function collectDeviceSignals() {
    const signals = {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        languages: navigator.languages ? navigator.languages.join(',') : '',
        screenResolution: `${screen.width}x${screen.height}`,
        colorDepth: screen.colorDepth,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        timezoneOffset: new Date().getTimezoneOffset(),
        deviceMemory: navigator.deviceMemory || null,
        hardwareConcurrency: navigator.hardwareConcurrency || null,
        pixelRatio: window.devicePixelRatio || 1,
        touchSupport: 'ontouchstart' in window ? 'yes' : 'no',
        cookiesEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack || 'unset',
        canvasFingerprint: getCanvasFingerprint(),
        webGLFingerprint: getWebGLFingerprint()
    };
    
    return signals;
}

function getCanvasFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = 200;
        canvas.height = 50;
        ctx.fillStyle = '#f60';
        ctx.fillRect(100, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.font = '14px Arial';
        ctx.fillText('CloudSentinel', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('Device Fingerprint', 4, 45);
        return canvas.toDataURL().slice(0, 100); // Truncated for efficiency
    } catch (e) {
        return 'canvas-error';
    }
}

function getWebGLFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) return 'no-webgl';
        
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown';
        const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown';
        
        return `${vendor}|${renderer}`;
    } catch (e) {
        return 'webgl-error';
    }
}

function sendDeviceSignals(url) {
    const signals = collectDeviceSignals();
    
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || ''
        },
        body: JSON.stringify(signals)
    }).then(response => response.json())
      .then(data => {
          if (data.device_id) {
              // Store device ID in session storage for future requests
              sessionStorage.setItem('cloudsentinel_device_id', data.device_id);
          }
      })
      .catch(error => console.error('Error sending device signals:', error));
}

// Auto-send device signals when page loads (if on login/OTP pages)
document.addEventListener('DOMContentLoaded', function() {
    if (window.location.pathname === '/login' || window.location.pathname === '/verify-otp' || window.location.pathname === '/waiting-admin-approval') {
        const deviceSignalsUrl = '/api/device-signals';
        // Delay slightly to ensure page is fully loaded
        setTimeout(() => sendDeviceSignals(deviceSignalsUrl), 500);
    }
});
