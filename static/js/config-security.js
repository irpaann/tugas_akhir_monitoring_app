// static/js/config-security.js

export const SecurityConfig = {
    detectionMode: 'rule-based', 
    
    // Daftar IP yang diblokir (nanti bisa diisi dari database)
    blacklistedIPs: [], 

    patterns: [
        // Kita tambah properti action: 'block' atau 'alert'
        { name: "SQL Injection", regex: /or\s+1=1/i, action: 'block' },
        { name: "XSS", regex: /<script.*?>/i, action: 'block' },
        { name: "Path Traversal", regex: /\/\.\./, action: 'block' },
        { name: "Suspicious", regex: /--/, action: 'alert' }
    ]
};

export function checkThreat(payload, ip) {
    // 1. Cek apakah IP ini sudah ada di daftar blokir
    if (SecurityConfig.blacklistedIPs.includes(ip)) {
        return { isSuspicious: true, type: "BLOCKED IP", action: 'block' };
    }

    if (!payload) return { isSuspicious: false, type: "Normal", action: 'none' };

    if (SecurityConfig.detectionMode === 'rule-based') {
        for (const p of SecurityConfig.patterns) {
            if (p.regex.test(payload)) {
                return { 
                    isSuspicious: true, 
                    type: p.name, 
                    action: p.action // Mengambil action dari rule
                };
            }
        }
    }
    
    return { isSuspicious: false, type: "Normal", action: 'none' };
}