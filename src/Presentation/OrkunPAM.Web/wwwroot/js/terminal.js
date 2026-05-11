// OrkunPAM HTML5 SSH Terminal - xterm.js + WebSocket bridge
// ES Module loaded via Blazor JS interop (import '/js/terminal.js')
import { Terminal } from 'https://esm.sh/xterm@5.3.0';
import { FitAddon } from 'https://esm.sh/@xterm/addon-fit@0.10.0';

let term = null;
let ws = null;
let fitAddon = null;
let resizeObserver = null;

// Encode UTF-8 string to base64 (handles non-ASCII characters)
function encodeInput(str) {
    const bytes = new TextEncoder().encode(str);
    let binary = '';
    bytes.forEach(b => binary += String.fromCharCode(b));
    return btoa(binary);
}

export function initTerminal(containerId, apiBase, deviceId, credentialId) {
    const container = document.getElementById(containerId);
    if (!container) { console.error('[OrkunPAM] Terminal container not found:', containerId); return; }

    // JWT stored in localStorage after login (key: 'orkunpam_token')
    const jwt = localStorage.getItem('orkunpam_token') ||
                sessionStorage.getItem('orkunpam_token') || '';

    term = new Terminal({
        cursorBlink: true,
        fontFamily: '"Cascadia Code", "Fira Code", Consolas, monospace',
        fontSize: 14,
        lineHeight: 1.2,
        scrollback: 5000,
        theme: {
            background: '#1e1e1e',
            foreground: '#d4d4d4',
            cursor: '#aeafad',
            selectionBackground: '#264f78',
            black: '#1e1e1e', brightBlack: '#808080',
            red: '#f44747', brightRed: '#f44747',
            green: '#6a9955', brightGreen: '#b5cea8',
            yellow: '#d7ba7d', brightYellow: '#d7ba7d',
            blue: '#569cd6', brightBlue: '#9cdcfe',
            magenta: '#c586c0', brightMagenta: '#c586c0',
            cyan: '#4ec9b0', brightCyan: '#4ec9b0',
            white: '#d4d4d4', brightWhite: '#ffffff'
        }
    });

    fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(container);

    // Small delay to allow DOM layout before fit
    setTimeout(() => { try { fitAddon.fit(); } catch { } }, 50);

    const dims = { cols: term.cols, rows: term.rows };
    const wsProto = apiBase.startsWith('https') ? 'wss' : 'ws';
    const wsBase = apiBase.replace(/^https?:\/\//, `${wsProto}://`);
    const wsUrl = `${wsBase}/ws/ssh?deviceId=${encodeURIComponent(deviceId)}` +
                  `&credentialId=${encodeURIComponent(credentialId)}` +
                  `&token=${encodeURIComponent(jwt)}` +
                  `&cols=${dims.cols}&rows=${dims.rows}`;

    term.write('\r\n\x1b[36m Connecting to OrkunPAM SSH gateway...\x1b[0m\r\n');

    ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
        term.write('\x1b[36m WebSocket established, authenticating...\x1b[0m\r\n');
    };

    ws.onmessage = (e) => {
        if (e.data instanceof ArrayBuffer) {
            // Binary frame = raw terminal output
            term.write(new Uint8Array(e.data));
        } else {
            try {
                const msg = JSON.parse(e.data);
                if (msg.t === 'connected') {
                    term.write('\x1b[32m SSH session established.\x1b[0m\r\n\r\n');
                } else if (msg.t === 'error') {
                    term.write(`\r\n\x1b[31m Error: ${msg.msg}\x1b[0m\r\n`);
                }
            } catch {
                // Unexpected text frame - display as-is
                term.write(e.data);
            }
        }
    };

    ws.onclose = (e) => {
        const reason = e.reason ? ` (${e.reason})` : '';
        term.write(`\r\n\r\n\x1b[33m Session closed${reason}.\x1b[0m\r\n`);
    };

    ws.onerror = () => {
        term.write('\r\n\x1b[31m WebSocket error. Check network and authentication.\x1b[0m\r\n');
    };

    // User keystroke -> SSH stdin (JSON: {t:"i", d:"<base64>"})
    term.onData(data => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ t: 'i', d: encodeInput(data) }));
        }
    });

    // Terminal resize -> SSH window-change (JSON: {t:"r", c:cols, r:rows})
    term.onResize(({ cols, rows }) => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ t: 'r', c: cols, r: rows }));
        }
    });

    // Auto-resize terminal when browser window changes
    resizeObserver = new ResizeObserver(() => {
        try { fitAddon.fit(); } catch { }
    });
    resizeObserver.observe(container);
}

export function disposeTerminal() {
    resizeObserver?.disconnect();
    resizeObserver = null;
    if (ws && ws.readyState === WebSocket.OPEN) ws.close(1000, 'User disconnected');
    ws = null;
    term?.dispose();
    term = null;
    fitAddon = null;
}
