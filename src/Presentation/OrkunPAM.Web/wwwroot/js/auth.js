// OrkunPAM Auth helpers — token storage in localStorage

export function storeToken(token, username) {
    if (token) localStorage.setItem('orkunpam_token', token);
    if (username) localStorage.setItem('orkunpam_user', username);
}

export function getToken() {
    return localStorage.getItem('orkunpam_token') || '';
}

export function getUsername() {
    return localStorage.getItem('orkunpam_user') || '';
}

export function clearToken() {
    localStorage.removeItem('orkunpam_token');
    localStorage.removeItem('orkunpam_user');
}

export function isAuthenticated() {
    return !!localStorage.getItem('orkunpam_token');
}
