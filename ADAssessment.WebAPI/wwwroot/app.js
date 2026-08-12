document.addEventListener('DOMContentLoaded', () => {
    const API_BASE = '/api';
    let jwtToken = localStorage.getItem('jwt_token') || '';

    // DOM Elementleri
    const loginSection = document.getElementById('loginSection');
    const dashboardSection = document.getElementById('dashboardSection');
    const loginForm = document.getElementById('loginForm');
    const loginError = document.getElementById('loginError');
    const logoutBtn = document.getElementById('logoutBtn');
    const runScanBtn = document.getElementById('runScanBtn');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const reportsList = document.getElementById('reportsList');
    const activeRulesList = document.getElementById('activeRulesList');
    const noCodeRuleForm = document.getElementById('noCodeRuleForm');
    const nocodeAlert = document.getElementById('nocodeAlert');

    // Stats
    const statUsers = document.getElementById('statUsers');
    const statRules = document.getElementById('statRules');
    const statVulnerabilities = document.getElementById('statVulnerabilities');

    // Başlangıç Durum Kontrolü
    if (jwtToken) {
        showDashboard();
    } else {
        showLogin();
    }

    // 1. JWT LOGIN
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginError.classList.add('hidden');

        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        try {
            const res = await fetch(`${API_BASE}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await res.json();

            if (res.ok && data.token) {
                jwtToken = data.token;
                localStorage.setItem('jwt_token', jwtToken);
                localStorage.setItem('jwt_username', username);
                showDashboard();
            } else {
                loginError.textContent = data.message || 'Giriş başarısız. Kullanıcı adı veya şifre hatalı.';
                loginError.classList.remove('hidden');
            }
        } catch (err) {
            loginError.textContent = 'Sunucuya bağlanılamadı. Lütfen sunucunun çalıştığından emin olun.';
            loginError.classList.remove('hidden');
        }
    });

    // 2. LOGOUT
    logoutBtn.addEventListener('click', () => {
        localStorage.removeItem('jwt_token');
        localStorage.removeItem('jwt_username');
        jwtToken = '';
        showLogin();
    });

    // 3. TARAMA BAŞLAT (POST /api/assessment/scan)
    runScanBtn.addEventListener('click', async () => {
        loadingSpinner.classList.remove('hidden');
        reportsList.innerHTML = '';

        try {
            const res = await fetch(`${API_BASE}/assessment/scan`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${jwtToken}`,
                    'Content-Type': 'application/json'
                }
            });

            const data = await res.json();
            loadingSpinner.classList.add('hidden');

            if (res.ok) {
                statUsers.textContent = data.scannedUserCount;
                statRules.textContent = data.totalRulesExecuted;
                statVulnerabilities.textContent = data.vulnerableRulesCount;

                renderReports(data.results);
            } else if (res.status === 401) {
                alert('Oturum süreniz doldu. Lütfen tekrar giriş yapın.');
                logoutBtn.click();
            } else {
                reportsList.innerHTML = `<div class="alert alert-danger">Tarama Hatası: ${data.message || 'Bilinmeyen hata'}</div>`;
            }
        } catch (err) {
            loadingSpinner.classList.add('hidden');
            reportsList.innerHTML = `<div class="alert alert-danger">Baglantı Hatası: ${err.message}</div>`;
        }
    });

    // 4. NO-CODE KURAL EKLE (POST /api/rules)
    noCodeRuleForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        nocodeAlert.classList.add('hidden');

        const ruleDefinition = {
            ruleId: document.getElementById('ruleId').value,
            name: document.getElementById('ruleName').value,
            description: document.getElementById('ruleDesc').value,
            targetProperty: document.getElementById('targetProperty').value,
            operator: document.getElementById('operator').value,
            value: document.getElementById('ruleValue').value,
            condition: document.getElementById('condition').value,
            riskLevel: document.getElementById('riskLevel').value,
            remediation: document.getElementById('remediation').value,
            frameworkMapping: 'No-Code Web UI Generator'
        };

        try {
            const res = await fetch(`${API_BASE}/rules`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${jwtToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(ruleDefinition)
            });

            const data = await res.json();

            if (res.ok) {
                nocodeAlert.className = 'alert alert-success';
                nocodeAlert.textContent = '🎉 No-Code JSON Kuralı Başarıyla Oluşturuldu ve Sisteme Eklendi!';
                nocodeAlert.classList.remove('hidden');
                noCodeRuleForm.reset();
                loadActiveRules();
            } else {
                nocodeAlert.className = 'alert alert-danger';
                nocodeAlert.textContent = data.message || 'Kural eklenirken hata oluştu.';
                nocodeAlert.classList.remove('hidden');
            }
        } catch (err) {
            nocodeAlert.className = 'alert alert-danger';
            nocodeAlert.textContent = 'Bağlantı hatası oluştu.';
            nocodeAlert.classList.remove('hidden');
        }
    });

    // SEKME DEĞİŞTİRME MANTIĞI
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));

            e.target.classList.add('active');
            const targetTab = e.target.getAttribute('data-tab');
            document.getElementById(targetTab).classList.remove('hidden');

            if (targetTab === 'activeRulesTab') {
                loadActiveRules();
            }
        });
    });

    // RAPORLARI EKRANA BASTIRMA
    function renderReports(results) {
        reportsList.innerHTML = '';

        if (!results || results.length === 0) {
            reportsList.innerHTML = '<div class="alert alert-success">Sistemde herhangi bir zafiyet bulunamadı.</div>';
            return;
        }

        results.forEach(rule => {
            const isVuln = rule.isVulnerable;
            const card = document.createElement('div');
            const riskClass = rule.riskLevel.toLowerCase() + '-risk';

            card.className = `vuln-card ${isVuln ? riskClass : 'low-risk'}`;

            let affectedHtml = '';
            if (isVuln && rule.affectedObjects) {
                affectedHtml = '<div class="affected-list">' +
                    rule.affectedObjects.map(obj => `<span class="tag-affected">${obj}</span>`).join('') +
                    '</div>';
            }

            card.innerHTML = `
                <div class="vuln-header">
                    <span class="vuln-title">${rule.ruleId} - ${rule.name || rule.ruleId}</span>
                    <span class="badge badge-risk-${rule.riskLevel.toLowerCase()}">${isVuln ? 'ZAFİYET BULUNDU (' + rule.riskLevel + ')' : 'GÜVENLİ'}</span>
                </div>
                ${affectedHtml}
                ${isVuln ? `<div class="remediation-box"><strong>💡 Çözüm Önerisi:</strong><br>${rule.remediation}</div>` : ''}
            `;

            reportsList.appendChild(card);
        });
    }

    // AKTİF KURALLARI YÜKLE
    async function loadActiveRules() {
        activeRulesList.innerHTML = '<p>Kurallar yükleniyor...</p>';
        try {
            const res = await fetch(`${API_BASE}/rules`, {
                headers: { 'Authorization': `Bearer ${jwtToken}` }
            });
            const rules = await res.json();

            activeRulesList.innerHTML = '';
            rules.forEach(r => {
                const item = document.createElement('div');
                item.className = 'vuln-card low-risk';
                item.innerHTML = `
                    <div class="vuln-header">
                        <span class="vuln-title">${r.ruleId} - ${r.name}</span>
                        <span class="badge badge-risk-low">${r.frameworkMapping || 'Uyum Kuralı'}</span>
                    </div>
                    <p style="color: #94a3b8; font-size: 13px;">${r.description}</p>
                `;
                activeRulesList.appendChild(item);
            });
        } catch (err) {
            activeRulesList.innerHTML = '<p class="alert alert-danger">Kurallar yüklenirken hata oluştu.</p>';
        }
    }

    function showDashboard() {
        loginSection.classList.add('hidden');
        dashboardSection.classList.remove('hidden');
        const displayName = localStorage.getItem('jwt_username') || 'Kullanıcı';
        document.getElementById('userBadge').textContent = `Oturum Açık: ${displayName} (Security Analyst)`;
    }

    function showLogin() {
        dashboardSection.classList.add('hidden');
        loginSection.classList.remove('hidden');
    }
});
