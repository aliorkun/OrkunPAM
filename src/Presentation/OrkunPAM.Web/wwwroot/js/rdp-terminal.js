// OrkunPAM HTML5 RDP Terminal
// Browser-side renderer: WebSocket <- Canvas (putImageData) + keyboard/mouse -> RDP input
// ES module, loaded via Blazor JS interop (import '/js/rdp-terminal.js')

let ws = null;
let canvas = null;
let ctx = null;
let desktopWidth = 1280;
let desktopHeight = 800;
let connected = false;
let resizeObserver = null;

// Scan code map for common keys (US QWERTY layout)
const KEY_SCAN_CODES = {
    'Escape': 0x01, 'F1': 0x3B, 'F2': 0x3C, 'F3': 0x3D, 'F4': 0x3E,
    'F5': 0x3F, 'F6': 0x40, 'F7': 0x41, 'F8': 0x42, 'F9': 0x43,
    'F10': 0x44, 'F11': 0x57, 'F12': 0x58,
    'Backquote': 0x29, 'Digit1': 0x02, 'Digit2': 0x03, 'Digit3': 0x04,
    'Digit4': 0x05, 'Digit5': 0x06, 'Digit6': 0x07, 'Digit7': 0x08,
    'Digit8': 0x09, 'Digit9': 0x0A, 'Digit0': 0x0B, 'Minus': 0x0C,
    'Equal': 0x0D, 'Backspace': 0x0E, 'Tab': 0x0F,
    'KeyQ': 0x10, 'KeyW': 0x11, 'KeyE': 0x12, 'KeyR': 0x13, 'KeyT': 0x14,
    'KeyY': 0x15, 'KeyU': 0x16, 'KeyI': 0x17, 'KeyO': 0x18, 'KeyP': 0x19,
    'BracketLeft': 0x1A, 'BracketRight': 0x1B, 'Enter': 0x1C,
    'ControlLeft': 0x1D, 'ControlRight': 0x1D,
    'KeyA': 0x1E, 'KeyS': 0x1F, 'KeyD': 0x20, 'KeyF': 0x21, 'KeyG': 0x22,
    'KeyH': 0x23, 'KeyJ': 0x24, 'KeyK': 0x25, 'KeyL': 0x26,
    'Semicolon': 0x27, 'Quote': 0x28, 'Backslash': 0x2B,
    'ShiftLeft': 0x2A, 'ShiftRight': 0x36,
    'IntlBackslash': 0x56,
    'KeyZ': 0x2C, 'KeyX': 0x2D, 'KeyC': 0x2E, 'KeyV': 0x2F, 'KeyB': 0x30,
    'KeyN': 0x31, 'KeyM': 0x32, 'Comma': 0x33, 'Period': 0x34, 'Slash': 0x35,
    'AltLeft': 0x38, 'AltRight': 0x38, 'Space': 0x39,
    'CapsLock': 0x3A, 'NumLock': 0x45, 'ScrollLock': 0x46,
    'Home': 0x47, 'ArrowUp': 0x48, 'PageUp': 0x49,
    'ArrowLeft': 0x4B, 'ArrowRight': 0x4D,
    'End': 0x4F, 'ArrowDown': 0x50, 'PageDown': 0x51,
    'Insert': 0x52, 'Delete': 0x53,
    'Numpad0': 0x52, 'Numpad1': 0x4F, 'Numpad2': 0x50, 'Numpad3': 0x51,
    'Numpad4': 0x4B, 'Numpad5': 0x4C, 'Numpad6': 0x4D,
    'Numpad7': 0x47, 'Numpad8': 0x48, 'Numpad9': 0x49,
    'NumpadDecimal': 0x53, 'NumpadAdd': 0x4E, 'NumpadSubtract': 0x4A,
    'NumpadMultiply': 0x37, 'NumpadDivide': 0x35, 'NumpadEnter': 0x1C,
    'MetaLeft': 0x5B, 'MetaRight': 0x5C, 'ContextMenu': 0x5D,
};

// Mouse pointer flags
const PTRFLAGS_MOVE    = 0x0800;
const PTRFLAGS_DOWN    = 0x8000;
const PTRFLAGS_BUTTON1 = 0x1000; // left
const PTRFLAGS_BUTTON2 = 0x2000; // right
const PTRFLAGS_BUTTON3 = 0x4000; // middle

function getCanvasPos(e) {
    const rect = canvas.getBoundingClientRect();
    const scaleX = desktopWidth  / rect.width;
    const scaleY = desktopHeight / rect.height;
    return {
        x: Math.round((e.clientX - rect.left) * scaleX),
        y: Math.round((e.clientY - rect.top)  * scaleY)
    };
}

export function initRdpTerminal(containerId, apiBase, deviceId, credentialId) {
    const container = document.getElementById(containerId);
    if (!container) { console.error('[WebRDP] Container not found:', containerId); return; }

    // Create canvas
    canvas = document.createElement('canvas');
    canvas.style.cssText = 'width:100%;height:100%;display:block;cursor:default;background:#000;';
    canvas.width  = desktopWidth;
    canvas.height = desktopHeight;
    container.appendChild(canvas);
    ctx = canvas.getContext('2d', { alpha: false });

    // Status overlay
    const status = document.createElement('div');
    status.id = 'rdp-status';
    status.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);' +
        'color:#4ec9b0;font-family:monospace;font-size:14px;pointer-events:none;';
    status.textContent = ' Connecting to RDP server…';
    container.style.position = 'relative';
    container.appendChild(status);

    const jwt = localStorage.getItem('orkunpam_token') ||
                sessionStorage.getItem('orkunpam_token') || '';

    const wsProto = apiBase.startsWith('https') ? 'wss' : 'ws';
    const wsBase  = apiBase.replace(/^https?:\/\//, `${wsProto}://`);
    const wsUrl   = `${wsBase}/ws/rdp?deviceId=${encodeURIComponent(deviceId)}` +
                    `&credentialId=${encodeURIComponent(credentialId)}` +
                    `&token=${encodeURIComponent(jwt)}` +
                    `&width=${desktopWidth}&height=${desktopHeight}`;

    ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
        status.textContent = ' Authenticating…';
    };

    ws.onmessage = (e) => {
        if (e.data instanceof ArrayBuffer) {
            handleBinaryFrame(new DataView(e.data));
        } else {
            try {
                const msg = JSON.parse(e.data);
                if (msg.t === 'connected') {
                    connected = true;
                    status.style.display = 'none';
                    canvas.focus();
                } else if (msg.t === 'error') {
                    status.style.color = '#f44747';
                    status.textContent = ` Error: ${msg.msg}`;
                }
            } catch { }
        }
    };

    ws.onclose = (e) => {
        connected = false;
        status.style.display = 'block';
        status.style.color = '#d7ba7d';
        status.textContent = ` Session closed${e.reason ? ': ' + e.reason : ''}.`;
    };

    ws.onerror = () => {
        status.style.color = '#f44747';
        status.textContent = ' WebSocket error — check network.';
    };

    // Keyboard events
    canvas.tabIndex = 0;
    canvas.addEventListener('keydown', onKeyDown);
    canvas.addEventListener('keyup',   onKeyUp);
    canvas.addEventListener('contextmenu', e => e.preventDefault());

    // Mouse events
    canvas.addEventListener('mousemove',  onMouseMove);
    canvas.addEventListener('mousedown',  onMouseDown);
    canvas.addEventListener('mouseup',    onMouseUp);
    canvas.addEventListener('wheel',      onMouseWheel, { passive: false });

    // Resize — keep canvas aspect ratio
    resizeObserver = new ResizeObserver(() => resizeCanvas(container));
    resizeObserver.observe(container);
    resizeCanvas(container);
}

function resizeCanvas(container) {
    if (!canvas) return;
    const cw = container.clientWidth;
    const ch = container.clientHeight;
    const scale = Math.min(cw / desktopWidth, ch / desktopHeight);
    canvas.style.width  = Math.round(desktopWidth  * scale) + 'px';
    canvas.style.height = Math.round(desktopHeight * scale) + 'px';
}

function handleBinaryFrame(view) {
    const type = view.getUint8(0);
    if (type === 0x02) {
        // Desktop size: [0x02][w:2LE][h:2LE]
        desktopWidth  = view.getUint16(1, true);
        desktopHeight = view.getUint16(3, true);
        canvas.width  = desktopWidth;
        canvas.height = desktopHeight;
    } else if (type === 0x01) {
        // Bitmap tile: [0x01][x:2LE][y:2LE][w:2LE][h:2LE][pixels:RGBA]
        const x = view.getUint16(1, true);
        const y = view.getUint16(3, true);
        const w = view.getUint16(5, true);
        const h = view.getUint16(7, true);
        const pixelBytes = new Uint8ClampedArray(view.buffer, 9, w * h * 4);
        const imageData = new ImageData(pixelBytes, w, h);
        ctx.putImageData(imageData, x, y);
    }
}

function onKeyDown(e) {
    e.preventDefault();
    const sc = KEY_SCAN_CODES[e.code];
    if (sc != null && ws && ws.readyState === WebSocket.OPEN)
        ws.send(JSON.stringify({ t: 'k', s: sc, r: false }));
}

function onKeyUp(e) {
    e.preventDefault();
    const sc = KEY_SCAN_CODES[e.code];
    if (sc != null && ws && ws.readyState === WebSocket.OPEN)
        ws.send(JSON.stringify({ t: 'k', s: sc, r: true }));
}

function onMouseMove(e) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const { x, y } = getCanvasPos(e);
    ws.send(JSON.stringify({ t: 'm', x, y, f: PTRFLAGS_MOVE }));
}

function onMouseDown(e) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    canvas.focus();
    const { x, y } = getCanvasPos(e);
    const btn = e.button === 0 ? PTRFLAGS_BUTTON1 : e.button === 2 ? PTRFLAGS_BUTTON2 : PTRFLAGS_BUTTON3;
    ws.send(JSON.stringify({ t: 'm', x, y, f: PTRFLAGS_DOWN | btn }));
}

function onMouseUp(e) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const { x, y } = getCanvasPos(e);
    const btn = e.button === 0 ? PTRFLAGS_BUTTON1 : e.button === 2 ? PTRFLAGS_BUTTON2 : PTRFLAGS_BUTTON3;
    ws.send(JSON.stringify({ t: 'm', x, y, f: btn }));
}

function onMouseWheel(e) {
    e.preventDefault();
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const { x, y } = getCanvasPos(e);
    // PTRFLAGS_WHEEL = 0x0200, direction in upper byte
    const delta = e.deltaY < 0 ? 0x0278 : 0x0288; // up or down
    ws.send(JSON.stringify({ t: 'm', x, y, f: delta }));
}

export function disposeRdpTerminal() {
    resizeObserver?.disconnect();
    resizeObserver = null;
    if (ws && ws.readyState === WebSocket.OPEN)
        ws.close(1000, 'User disconnected');
    ws = null;
    canvas?.removeEventListener('keydown', onKeyDown);
    canvas?.removeEventListener('keyup',   onKeyUp);
    canvas = null;
    ctx = null;
    connected = false;
}
