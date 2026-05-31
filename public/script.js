// ==================== CONFIGURACIÓN ====================
let currentResults = [];

// Elementos DOM
const domainInput = document.getElementById('domainInput');
const emailInput = document.getElementById('emailInput');
const lineInput = document.getElementById('lineInput');
const searchDomainBtn = document.getElementById('searchDomainBtn');
const searchEmailBtn = document.getElementById('searchEmailBtn');
const searchLineBtn = document.getElementById('searchLineBtn');
const resultsContainer = document.getElementById('resultsContainer');
const resultsCountSpan = document.getElementById('resultsCount');
const copyAllBtn = document.getElementById('copyAllBtn');
const exportBtn = document.getElementById('exportBtn');
const totalCredsSpan = document.getElementById('totalCreds');
const fileStatusSpan = document.getElementById('file-status');
const toast = document.getElementById('toast');

// ==================== HELPER FUNCTIONS ====================
function showToast(message, duration = 2500) {
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), duration);
}

function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function renderResults(results, searchTerm, type) {
    currentResults = results;
    
    if (!results || results.length === 0) {
        resultsContainer.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-ban"></i>
                <p>No se encontraron resultados para "${escapeHtml(searchTerm)}"</p>
            </div>
        `;
        resultsCountSpan.textContent = '0 resultados';
        copyAllBtn.style.display = 'none';
        exportBtn.style.display = 'none';
        return;
    }
    
    const html = results.map(res => `
        <div class="result-card">
            <div class="result-content">${escapeHtml(res.line)}</div>
            <div class="result-badge">ID: ${res.id || res.index || '?'}</div>
        </div>
    `).join('');
    
    resultsContainer.innerHTML = html;
    resultsCountSpan.textContent = `${results.length} resultado${results.length !== 1 ? 's' : ''}`;
    copyAllBtn.style.display = 'inline-flex';
    exportBtn.style.display = 'inline-flex';
}

function clearResults() {
    resultsContainer.innerHTML = `
        <div class="empty-state">
            <i class="fas fa-search"></i>
            <p>Realiza una búsqueda para ver resultados</p>
        </div>
    `;
    resultsCountSpan.textContent = '0 resultados';
    copyAllBtn.style.display = 'none';
    exportBtn.style.display = 'none';
    currentResults = [];
}

// ==================== API CALLS ====================
async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        if (response.ok) {
            const data = await response.json();
            totalCredsSpan.textContent = data.total_credentials.toLocaleString();
            fileStatusSpan.innerHTML = `✅ Servidor activo · ${data.total_credentials.toLocaleString()} credenciales`;
        } else {
            fileStatusSpan.innerHTML = '⚠️ Error al conectar con el servidor';
        }
    } catch (error) {
        console.error('Error fetching stats:', error);
        fileStatusSpan.innerHTML = '⚠️ Servidor no disponible';
    }
}

async function searchByDomain(domain) {
    if (!domain || domain.trim() === '') {
        showToast('Ingresa un dominio para buscar', 1500);
        return [];
    }
    
    showToast(`🔍 Buscando dominio: ${domain}...`, 1000);
    
    try {
        const response = await fetch(`/api/search/domain?q=${encodeURIComponent(domain)}`);
        if (!response.ok) throw new Error('Error en la búsqueda');
        
        const data = await response.json();
        const results = data.results.map(r => ({ line: r.line, id: r.id }));
        renderResults(results, domain, 'domain');
        return results;
    } catch (error) {
        console.error('Error:', error);
        showToast('Error al buscar. ¿El servidor está corriendo?', 3000);
        return [];
    }
}

async function searchByEmail(email) {
    if (!email || email.trim() === '') {
        showToast('Ingresa un email para buscar', 1500);
        return [];
    }
    
    if (!email.includes('@')) {
        showToast('Ingresa un email válido (debe contener @)', 1500);
        return [];
    }
    
    showToast(`🔍 Buscando email: ${email}...`, 1000);
    
    try {
        const response = await fetch(`/api/search/email?q=${encodeURIComponent(email)}`);
        if (!response.ok) throw new Error('Error en la búsqueda');
        
        const data = await response.json();
        const results = data.results.map(r => ({ line: r.line, id: r.id }));
        renderResults(results, email, 'email');
        return results;
    } catch (error) {
        console.error('Error:', error);
        showToast('Error al buscar. ¿El servidor está corriendo?', 3000);
        return [];
    }
}

async function searchByLine(lineNumber) {
    if (!lineNumber || isNaN(lineNumber) || lineNumber < 1) {
        showToast('Ingresa un número de línea válido (mayor a 0)', 1500);
        return null;
    }
    
    showToast(`🔍 Buscando línea ${lineNumber}...`, 1000);
    
    try {
        const response = await fetch(`/api/search/line?num=${lineNumber}`);
        if (!response.ok) throw new Error('Error en la búsqueda');
        
        const data = await response.json();
        if (data.result) {
            const results = [{ line: data.result.line, id: data.result.id }];
            renderResults(results, `línea ${lineNumber}`, 'line');
            return results;
        } else {
            renderResults([], `línea ${lineNumber}`, 'line');
            showToast(`No se encontró la línea ${lineNumber}`, 1500);
            return null;
        }
    } catch (error) {
        console.error('Error:', error);
        showToast('Error al buscar. ¿El servidor está corriendo?', 3000);
        return null;
    }
}

// ==================== UTILIDADES ====================
function copyAllResults() {
    if (!currentResults.length) {
        showToast('No hay resultados para copiar', 1500);
        return;
    }
    
    const textToCopy = currentResults.map(r => r.line).join('\n');
    navigator.clipboard.writeText(textToCopy).then(() => {
        showToast(`📋 Copiados ${currentResults.length} resultados`, 2000);
    }).catch(() => showToast('Error al copiar', 1500));
}

function exportResults() {
    if (!currentResults.length) {
        showToast('No hay resultados para exportar', 1500);
        return;
    }
    
    const content = currentResults.map(r => r.line).join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `resultados_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('📥 Exportado correctamente', 2000);
}

// ==================== EVENT LISTENERS ====================
// Tabs
const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = {
    domain: document.getElementById('tab-domain'),
    email: document.getElementById('tab-email'),
    line: document.getElementById('tab-line')
};

tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        const tabId = btn.getAttribute('data-tab');
        
        tabBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        Object.values(tabContents).forEach(content => {
            if (content) content.classList.remove('active');
        });
        
        if (tabContents[tabId]) {
            tabContents[tabId].classList.add('active');
        }
    });
});

// Botones de búsqueda
searchDomainBtn.addEventListener('click', () => {
    const domain = domainInput.value.trim();
    if (domain) searchByDomain(domain);
    else showToast('Ingresa un dominio', 1500);
});

searchEmailBtn.addEventListener('click', () => {
    const email = emailInput.value.trim();
    if (email) searchByEmail(email);
    else showToast('Ingresa un email', 1500);
});

searchLineBtn.addEventListener('click', () => {
    const lineNum = parseInt(lineInput.value);
    if (!isNaN(lineNum) && lineNum > 0) searchByLine(lineNum);
    else showToast('Ingresa un número de línea válido', 1500);
});

// Enter key
domainInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') searchByDomain(domainInput.value.trim());
});
emailInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') searchByEmail(emailInput.value.trim());
});
lineInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') searchByLine(parseInt(lineInput.value));
});

// Botones de acción
copyAllBtn.addEventListener('click', copyAllResults);
exportBtn.addEventListener('click', exportResults);

// ==================== INIT ====================
async function init() {
    await fetchStats();
    clearResults();
    
    // Fetch stats cada 30 segundos
    setInterval(fetchStats, 30000);
}

init();