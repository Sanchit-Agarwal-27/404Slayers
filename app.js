/**
 * ChainGuard Frontend Application Logic
 *
 * Wires up the landing page, analysis page, and history page defined in
 * index.html to the API client in api.js. No framework — plain DOM.
 */

const state = {
    demoMode: null,       // set from /health
    currentResult: null,  // last successful analysis response
    requestSeq: 0,        // guards against out-of-order responses from rapid clicks
};

/**
 * Run an analysis request and render it, ignoring the response if a newer
 * request was started in the meantime (so a slow earlier request can never
 * overwrite a newer result).
 */
async function runAnalysis(fetchFn, fallbackMessage, onSuccess) {
    const seq = ++state.requestSeq;
    showPage('analysisPage');
    beginLoading();
    try {
        const result = await fetchFn();
        if (seq !== state.requestSeq) return;
        if (onSuccess) onSuccess(result);
        renderResult(result);
    } catch (error) {
        if (seq !== state.requestSeq) return;
        renderError((error && error.message) || fallbackMessage);
    }
}

// ----------------------------------------------------------------------
// Page navigation
// ----------------------------------------------------------------------

function showPage(pageId) {
    ['landingPage', 'analysisPage', 'historyPage'].forEach((id) => {
        document.getElementById(id).style.display = id === pageId ? '' : 'none';
    });
}

function goHome() {
    showPage('landingPage');
}

async function goHistory() {
    showPage('historyPage');
    await renderHistory();
}

// ----------------------------------------------------------------------
// Startup: health check, demo mode banner, demo shortcuts
// ----------------------------------------------------------------------

async function init() {
    const health = await ChainGuardAPI.checkHealth();

    if (!health) {
        document.getElementById('serverAlert').style.display = 'flex';
        return;
    }

    state.demoMode = !!health.demo_mode;
    document.getElementById('demoAlert').style.display = state.demoMode ? 'flex' : 'none';

    if (state.demoMode) {
        const container = document.getElementById('demoShortcuts');
        Object.entries(DEMO_SCENARIO_LABELS).forEach(([scenario, label]) => {
            const chip = document.createElement('button');
            chip.type = 'button';
            chip.className = 'demo-chip';
            chip.textContent = label;
            chip.addEventListener('click', () => runDemoScenario(scenario));
            container.appendChild(chip);
        });
    }
}

// ----------------------------------------------------------------------
// Analysis flow
// ----------------------------------------------------------------------

function setInputError(message) {
    const el = document.getElementById('inputError');
    if (!message) {
        el.style.display = 'none';
        el.textContent = '';
        return;
    }
    el.style.display = 'block';
    el.textContent = message;
}

async function handleAnalyzeClick() {
    const input = document.getElementById('addressInput');
    const address = input.value.trim();

    const validation = ChainGuardAPI.validateAddress(address);
    if (!validation.valid) {
        setInputError(validation.error);
        return;
    }
    setInputError(null);

    await runAnalysis(() => ChainGuardAPI.analyzeAddress(address), 'Analysis failed.');
}

async function runDemoScenario(scenario) {
    await runAnalysis(
        () => ChainGuardAPI.analyzeDemoScenario(scenario),
        'Demo analysis failed.',
        (result) => { document.getElementById('addressInput').value = result.address_info.address; },
    );
}

function beginLoading() {
    document.getElementById('loadingState').style.display = 'flex';
    document.getElementById('analysisContent').style.display = 'none';
    document.getElementById('errorAlert').style.display = 'none';
    document.getElementById('demoBanner').style.display = 'none';
    document.getElementById('resultsBody').style.display = 'none';
}

function renderError(message) {
    document.getElementById('loadingState').style.display = 'none';
    document.getElementById('analysisContent').style.display = 'block';
    document.getElementById('resultsBody').style.display = 'none';
    const errAlert = document.getElementById('errorAlert');
    errAlert.style.display = 'flex';
    document.getElementById('errorMessage').textContent = message;
}

function renderResult(result) {
    state.currentResult = result;

    document.getElementById('loadingState').style.display = 'none';
    document.getElementById('analysisContent').style.display = 'block';
    document.getElementById('errorAlert').style.display = 'none';
    document.getElementById('resultsBody').style.display = 'block';
    document.getElementById('demoBanner').style.display = result.is_demo_data ? 'flex' : 'none';

    renderScoreCard(result);
    renderAddressInfo(result);
    renderContractInfo(result);
    renderActivityMetrics(result);
    renderSignals(result.reputation_score.signals);
    renderGraph(result.interaction_graph, result.address_info.address);
    renderTransactions(result.recent_transactions, result.address_info.address);
    document.getElementById('recommendation').textContent = result.reputation_score.recommendation;
}

// ----------------------------------------------------------------------
// Rendering: score card
// ----------------------------------------------------------------------

function renderScoreCard(result) {
    const rep = result.reputation_score;
    document.getElementById('scoreValue').textContent = rep.score;

    const display = RISK_DISPLAY[rep.risk_level] || { cssClass: 'moderate', label: rep.risk_level.toUpperCase() };
    const riskEl = document.getElementById('riskLevel');
    riskEl.className = `risk-level ${display.cssClass}`;
    riskEl.textContent = display.label;

    document.getElementById('scoreReasoning').textContent = rep.reasoning;

    const tag = document.getElementById('dataSourceTag');
    if (result.is_demo_data) {
        tag.textContent = 'DEMO DATA';
        tag.className = 'data-source-tag demo';
    } else {
        tag.textContent = 'LIVE DATA';
        tag.className = 'data-source-tag live';
    }
}

// ----------------------------------------------------------------------
// Rendering: address / contract info
// ----------------------------------------------------------------------

function renderAddressInfo(result) {
    const info = result.address_info;
    document.getElementById('addressDisplay').textContent = info.address;
    document.getElementById('addressType').textContent =
        info.address_type === 'contract' ? 'Smart Contract' : info.address_type === 'eoa' ? 'Wallet (EOA)' : 'Unknown';
    document.getElementById('networkDisplay').textContent = info.chain;
    document.getElementById('firstSeen').textContent = info.activity_metrics.first_seen
        ? formatDate(info.activity_metrics.first_seen) : 'Unknown';
    document.getElementById('lastActive').textContent = info.activity_metrics.last_active
        ? formatDate(info.activity_metrics.last_active) : 'No activity recorded';
}

function renderContractInfo(result) {
    const card = document.getElementById('contractInfoCard');
    const contract = result.contract_info;
    if (!contract) {
        card.style.display = 'none';
        return;
    }
    card.style.display = 'block';
    document.getElementById('contractVerified').textContent = contract.is_verified ? 'Yes ✓' : 'No — unverified';
    document.getElementById('contractCompiler').textContent = contract.compiler_version || 'Unknown';
    document.getElementById('contractProxy').textContent = contract.has_proxy ? 'Yes' : 'No';
    document.getElementById('contractCreationBlock').textContent = contract.creation_block || 'Unknown';
}

function renderActivityMetrics(result) {
    const m = result.address_info.activity_metrics;
    document.getElementById('txCount').textContent = formatNumber(m.transaction_count);
    document.getElementById('counterparties').textContent = formatNumber(m.unique_counterparties);
    document.getElementById('contracts').textContent = formatNumber(m.unique_contracts);
    document.getElementById('tokens').textContent = formatNumber(m.token_transfers);
}

// ----------------------------------------------------------------------
// Rendering: signals
// ----------------------------------------------------------------------

function signalIcon(signalType) {
    if (signalType === 'positive') return '✅';
    if (signalType === 'negative') return '⚠️';
    return 'ℹ️';
}

function renderSignals(signals) {
    const container = document.getElementById('signalsContainer');
    container.innerHTML = '';

    if (!signals || signals.length === 0) {
        container.innerHTML = '<p class="empty-state">No signals were generated for this address.</p>';
        return;
    }

    signals.forEach((signal) => {
        const el = document.createElement('div');
        el.className = `signal ${signal.signal_type}`;

        const weightClass = signal.weight > 0 ? 'positive' : signal.weight < 0 ? 'negative' : '';
        const weightText = signal.weight > 0 ? `+${signal.weight}` : `${signal.weight}`;

        let evidenceHtml = '';
        if (signal.evidence) {
            if (Array.isArray(signal.evidence.matches)) {
                evidenceHtml = '<div class="signal-evidence">' + signal.evidence.matches.map((m) => `
                    <div class="evidence-match">
                        <strong>${escapeHtml(formatAddress(m.address, false))}</strong> — ${escapeHtml(m.risk_type || '')}
                        (${escapeHtml(m.severity || '')})<br>
                        ${escapeHtml(m.description || '')}
                        ${isSafeUrl(m.reference) ? `<br><a href="${escapeHtml(m.reference)}" target="_blank" rel="noopener noreferrer">source</a>` : ''}
                        <br><span class="text-muted">Source: ${escapeHtml(m.source || '')}</span>
                    </div>
                `).join('') + '</div>';
            } else {
                const parts = Object.entries(signal.evidence).map(([k, v]) => `${escapeHtml(k)}: ${escapeHtml(String(v))}`);
                evidenceHtml = `<div class="signal-evidence">${parts.join(' &middot; ')}</div>`;
            }
        }

        el.innerHTML = `
            <div class="signal-icon">${signalIcon(signal.signal_type)}</div>
            <div class="signal-content">
                <div class="signal-header">
                    <h4>${escapeHtml(signal.name)}</h4>
                    <span class="signal-severity ${escapeHtml(signal.severity || 'info')}">${escapeHtml(signal.severity || 'info')}</span>
                </div>
                <p>${escapeHtml(signal.description)}</p>
                ${evidenceHtml}
                <div class="signal-weight ${weightClass}">Score impact: ${weightText} &middot; Source: ${escapeHtml(signal.source)} &middot; Confidence: ${Math.round((signal.confidence ?? 1) * 100)}%</div>
            </div>
        `;
        container.appendChild(el);
    });
}

// ----------------------------------------------------------------------
// Rendering: interaction graph (deterministic circular SVG layout)
// ----------------------------------------------------------------------

function renderGraph(graph, centralAddress) {
    const container = document.getElementById('graphContainer');
    container.innerHTML = '';

    if (!graph || !graph.nodes || graph.nodes.length <= 1) {
        container.innerHTML = '<p class="graph-empty">No counterparty interactions to graph yet.</p>';
        return;
    }

    const width = 700;
    const height = 480;
    const cx = width / 2;
    const cy = height / 2;
    const radius = Math.min(width, height) / 2 - 70;

    const others = graph.nodes.filter((n) => !n.is_central);
    const angleStep = (2 * Math.PI) / Math.max(others.length, 1);

    const nodePositions = {};
    nodePositions[centralAddress.toLowerCase()] = { x: cx, y: cy };

    others.forEach((node, i) => {
        const angle = i * angleStep - Math.PI / 2;
        nodePositions[node.address.toLowerCase()] = {
            x: cx + radius * Math.cos(angle),
            y: cy + radius * Math.sin(angle),
        };
    });

    let svg = `<svg viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" style="width:100%; height:auto; min-width:600px;">`;

    // Edges first, so nodes render on top
    (graph.edges || []).forEach((edge) => {
        const from = nodePositions[edge.from_address.toLowerCase()];
        const to = nodePositions[edge.to_address.toLowerCase()];
        if (!from || !to) return;
        const strokeWidth = Math.min(1 + Math.log2(edge.count + 1), 6);
        svg += `<line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" stroke="#2a2a3e" stroke-width="${strokeWidth}" />`;
    });

    // Nodes
    graph.nodes.forEach((node) => {
        const pos = nodePositions[node.address.toLowerCase()];
        if (!pos) return;
        const r = node.is_central ? 16 : 9;
        let color = '#b0b0b0'; // default counterparty
        if (node.is_central) color = '#00d4ff';
        else if (node.is_flagged) color = '#ff4444';
        else if (node.type === 'contract') color = '#ffd700';

        svg += `<circle cx="${pos.x}" cy="${pos.y}" r="${r}" fill="${color}" stroke="#0f0f1e" stroke-width="2">
            <title>${escapeHtml(node.address)} (${escapeHtml(node.type)}${node.is_flagged ? ', FLAGGED' : ''}) — ${node.interaction_count} interaction(s)</title>
        </circle>`;

        if (!node.is_central) {
            svg += `<text x="${pos.x}" y="${pos.y + r + 12}" text-anchor="middle" fill="#b0b0b0" font-size="10" font-family="monospace">${escapeHtml(formatAddress(node.address))}</text>`;
        } else {
            svg += `<text x="${pos.x}" y="${pos.y - r - 8}" text-anchor="middle" fill="#00d4ff" font-size="11" font-family="monospace">${escapeHtml(formatAddress(node.address))} (central)</text>`;
        }
    });

    svg += '</svg>';
    container.innerHTML = svg;

    if (graph.truncated) {
        const note = document.createElement('p');
        note.className = 'text-muted';
        note.style.marginTop = '8px';
        note.textContent = 'Graph truncated to the top counterparties by interaction count.';
        container.appendChild(note);
    }
}

// ----------------------------------------------------------------------
// Rendering: transaction table
// ----------------------------------------------------------------------

function renderTransactions(transactions, centralAddress) {
    const wrapper = document.getElementById('txTableWrapper');

    if (!transactions || transactions.length === 0) {
        wrapper.innerHTML = '<p class="empty-state">No transactions found for this address on this chain.</p>';
        return;
    }

    let rows = transactions.map((tx) => `
        <tr>
            <td class="mono">${escapeHtml(formatAddress(tx.hash))}</td>
            <td><span class="tx-direction ${tx.direction}">${tx.direction}</span></td>
            <td class="mono">${escapeHtml(formatAddress(tx.direction === 'out' ? (tx.to_address || 'contract creation') : tx.from_address))}</td>
            <td>${tx.value.toFixed(4)}</td>
            <td>${escapeHtml(formatDate(tx.timestamp))}</td>
            <td>${tx.is_failed ? '<span class="tx-failed">FAILED</span>' : 'Success'}</td>
        </tr>
    `).join('');

    wrapper.innerHTML = `
        <table class="tx-table">
            <thead>
                <tr><th>Hash</th><th>Dir.</th><th>Counterparty</th><th>Value</th><th>Time</th><th>Status</th></tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;
}

// ----------------------------------------------------------------------
// History page
// ----------------------------------------------------------------------

async function renderHistory() {
    const list = document.getElementById('historyList');
    list.innerHTML = '<p class="text-center text-muted">Loading...</p>';

    const history = await ChainGuardAPI.getSearchHistory();

    if (!history.entries || history.entries.length === 0) {
        list.innerHTML = '<p class="text-center text-muted">No search history yet</p>';
        return;
    }

    list.innerHTML = '';
    history.entries.forEach((entry) => {
        const display = RISK_DISPLAY[entry.risk_level] || { cssClass: 'moderate', label: entry.risk_level.toUpperCase() };
        const item = document.createElement('div');
        item.className = 'history-item';
        item.innerHTML = `
            <div>
                <div class="history-item-address">${escapeHtml(formatAddress(entry.address, false))}</div>
                <div class="history-item-time">${escapeHtml(entry.chain)} &middot; ${escapeHtml(formatDate(entry.timestamp))} ${entry.is_demo ? '&middot; demo' : '&middot; live'}</div>
            </div>
            <div class="history-item-score">${entry.score}</div>
            <div class="history-item-risk risk-level ${display.cssClass}">${display.label}</div>
        `;
        item.addEventListener('click', () => reanalyzeFromHistory(entry.address, entry.chain));
        list.appendChild(item);
    });
}

async function reanalyzeFromHistory(address, chain) {
    document.getElementById('addressInput').value = address;
    await runAnalysis(() => ChainGuardAPI.analyzeAddress(address, chain || 'ethereum_mainnet'), 'Analysis failed.');
}

// ----------------------------------------------------------------------
// Utilities
// ----------------------------------------------------------------------

// Only http(s) links are rendered as clickable (guards against javascript: URLs).
function isSafeUrl(url) {
    return typeof url === 'string' && /^https?:\/\//i.test(url);
}

function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ----------------------------------------------------------------------
// Wire up event listeners
// ----------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('analyzeBtn').addEventListener('click', handleAnalyzeClick);
    document.getElementById('addressInput').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleAnalyzeClick();
    });
    document.getElementById('backBtn').addEventListener('click', goHome);
    document.getElementById('backFromHistoryBtn').addEventListener('click', goHome);
    document.getElementById('homeLink').addEventListener('click', (e) => { e.preventDefault(); goHome(); });
    document.getElementById('historyLink').addEventListener('click', (e) => { e.preventDefault(); goHistory(); });

    init();
});
