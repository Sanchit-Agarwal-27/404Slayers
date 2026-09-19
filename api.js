/**
 * ChainGuard API Client
 *
 * Thin wrapper around the backend REST API. Contains no business logic —
 * app.js is responsible for rendering and state.
 */

const API_BASE_URL = '/api';

class ChainGuardAPI {

    /**
     * Analyze a blockchain address.
     */
    static async analyzeAddress(address, chain = 'ethereum_mainnet') {
        const response = await fetch(`${API_BASE_URL}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                address: address,
                chain: chain,
                include_transactions: true,
                include_graph: true,
            }),
        });

        if (!response.ok) {
            throw new Error(await ChainGuardAPI._errorMessage(response));
        }
        return await response.json();
    }

    /**
     * Run one of the four fixed offline demo scenarios.
     * scenario is one of: low_risk_wallet, suspicious_contract, active_defi_wallet, high_risk_wallet
     */
    static async analyzeDemoScenario(scenario) {
        const response = await fetch(`${API_BASE_URL}/analyze/demo/${scenario}`);
        if (!response.ok) {
            throw new Error(await ChainGuardAPI._errorMessage(response));
        }
        return await response.json();
    }

    /**
     * Get a previously cached analysis for an address.
     */
    static async getAddressAnalysis(address, chain = 'ethereum_mainnet') {
        const response = await fetch(`${API_BASE_URL}/address/${address}?chain=${chain}`);
        if (!response.ok) {
            throw new Error(await ChainGuardAPI._errorMessage(response));
        }
        return await response.json();
    }

    /**
     * Get search history.
     */
    static async getSearchHistory() {
        try {
            const response = await fetch(`${API_BASE_URL}/history`);
            if (!response.ok) return { entries: [], total_count: 0 };
            return await response.json();
        } catch (error) {
            console.error('History fetch error:', error);
            return { entries: [], total_count: 0 };
        }
    }

    /**
     * Check backend health / mode.
     */
    static async checkHealth() {
        try {
            const response = await fetch('/health');
            if (!response.ok) return null;
            return await response.json();
        } catch (error) {
            console.error('Health check error:', error);
            return null;
        }
    }

    static async _errorMessage(response) {
        try {
            const body = await response.json();
            // FastAPI returns a string for HTTPException but a list of
            // {loc, msg, ...} objects for request-validation (422) errors.
            if (Array.isArray(body.detail)) {
                return body.detail.map((d) => d.msg || JSON.stringify(d)).join('; ');
            }
            return body.detail || `HTTP ${response.status}`;
        } catch (e) {
            return `HTTP ${response.status}`;
        }
    }

    /**
     * Client-side EVM address format check (server re-validates authoritatively).
     */
    static validateAddress(address) {
        if (!address || !address.startsWith('0x') || address.length !== 42) {
            return { valid: false, error: 'Address must be 0x followed by 40 hex characters.' };
        }
        if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
            return { valid: false, error: 'Address contains invalid hex characters.' };
        }
        return { valid: true };
    }
}

function formatAddress(address, truncate = true) {
    if (!address) return '';
    if (!truncate) return address;
    return address.substring(0, 6) + '...' + address.substring(address.length - 4);
}

function formatDate(dateString) {
    if (!dateString) return 'Unknown';
    try {
        // The backend emits timezone-naive UTC timestamps (no "Z"). Without a
        // marker JavaScript would parse them as *local* time and skew every date.
        let iso = String(dateString);
        if (!/(Z|[+-]\d{2}:?\d{2})$/.test(iso)) iso += 'Z';
        const date = new Date(iso);
        if (isNaN(date.getTime())) return String(dateString);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    } catch (e) {
        return String(dateString);
    }
}

function formatNumber(num) {
    if (num === null || num === undefined) return '--';
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

// Risk level -> display metadata. Keys match the API's RiskLevel enum values.
const RISK_DISPLAY = {
    'critical': { cssClass: 'critical', label: 'CRITICAL RISK' },
    'high': { cssClass: 'high', label: 'HIGH RISK' },
    'moderate': { cssClass: 'moderate', label: 'MODERATE RISK' },
    'low': { cssClass: 'low', label: 'LOW RISK' },
    'very_low': { cssClass: 'very-low', label: 'VERY LOW RISK' },
};

const DEMO_SCENARIO_LABELS = {
    'low_risk_wallet': 'Try: Low-risk wallet',
    'suspicious_contract': 'Try: Suspicious contract',
    'active_defi_wallet': 'Try: Active DeFi wallet',
    'high_risk_wallet': 'Try: High-risk wallet',
};
