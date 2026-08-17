document.addEventListener('DOMContentLoaded', () => {
    const API_BASE = '/api';
    let jwtToken = localStorage.getItem('jwt_token') || '';
    let editingRuleId = null;
    let currentRulesCache = [];

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
    const nocodeSubmitBtn = document.getElementById('nocodeSubmitBtn');
    const nocodeCancelEditBtn = document.getElementById('nocodeCancelEditBtn');
    const ruleIdInput = document.getElementById('ruleId');

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

    // Sunucudan gelen yanıtı güvenli şekilde JSON'a çevirir - gövdesi boş olan
    // yanıtlarda (ör. varsayılan 401 challenge) res.json() istisna fırlatabildiğinden
    // her fetch çağrısı bu yardımcıyı kullanır.
    async function safeParseJson(res) {
        try {
            return await res.json();
        } catch {
            return {};
        }
    }

    function handleUnauthorized() {
        alert('Oturum süreniz doldu. Lütfen tekrar giriş yapın.');
        logoutBtn.click();
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

            const data = await safeParseJson(res);

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

            loadingSpinner.classList.add('hidden');

            if (res.status === 401) {
                handleUnauthorized();
                return;
            }

            const data = await safeParseJson(res);

            if (res.ok) {
                statUsers.textContent = data.scannedUserCount;
                statRules.textContent = data.totalRulesExecuted;
                statVulnerabilities.textContent = data.vulnerableRulesCount;

                renderReports(data.results);
            } else {
                reportsList.innerHTML = `<div class="alert alert-danger">Tarama Hatası: ${data.message || 'Bilinmeyen hata'}</div>`;
            }
        } catch (err) {
            loadingSpinner.classList.add('hidden');
            reportsList.innerHTML = `<div class="alert alert-danger">Bağlantı Hatası: ${err.message}</div>`;
        }
    });

    // 4. NO-CODE KURAL EKLE / DÜZENLE (POST veya PUT /api/rules)
    noCodeRuleForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        nocodeAlert.classList.add('hidden');

        const ruleDefinition = {
            ruleId: ruleIdInput.value,
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

        const isEditing = !!editingRuleId;
        const url = isEditing ? `${API_BASE}/rules/${encodeURIComponent(editingRuleId)}` : `${API_BASE}/rules`;
        const method = isEditing ? 'PUT' : 'POST';

        try {
            const res = await fetch(url, {
                method,
                headers: {
                    'Authorization': `Bearer ${jwtToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(ruleDefinition)
            });

            if (res.status === 401) {
                handleUnauthorized();
                return;
            }

            const data = await safeParseJson(res);

            if (res.ok) {
                nocodeAlert.className = 'alert alert-success';
                nocodeAlert.textContent = isEditing
                    ? '✅ No-Code JSON Kuralı Başarıyla Güncellendi!'
                    : '🎉 No-Code JSON Kuralı Başarıyla Oluşturuldu ve Sisteme Eklendi!';
                nocodeAlert.classList.remove('hidden');
                cancelEdit();
                loadActiveRules();
            } else {
                nocodeAlert.className = 'alert alert-danger';
                nocodeAlert.textContent = data.message || 'Kural kaydedilirken hata oluştu.';
                nocodeAlert.classList.remove('hidden');
            }
        } catch (err) {
            nocodeAlert.className = 'alert alert-danger';
            nocodeAlert.textContent = 'Bağlantı hatası oluştu.';
            nocodeAlert.classList.remove('hidden');
        }
    });

    nocodeCancelEditBtn.addEventListener('click', () => {
        cancelEdit();
        nocodeAlert.classList.add('hidden');
    });

    // 5. AKTİF KURALLAR: DÜZENLE / SİL (event delegation)
    activeRulesList.addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;

        const ruleId = btn.dataset.ruleId;
        if (btn.dataset.action === 'delete') {
            deleteRule(ruleId);
        } else if (btn.dataset.action === 'edit') {
            const rule = currentRulesCache.find(r => r.ruleId === ruleId);
            if (rule) startEditRule(rule);
        }
    });

    async function deleteRule(ruleId) {
        if (!confirm(`'${ruleId}' kuralını silmek istediğinize emin misiniz?`)) return;

        try {
            const res = await fetch(`${API_BASE}/rules/${encodeURIComponent(ruleId)}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${jwtToken}` }
            });

            if (res.status === 401) {
                handleUnauthorized();
                return;
            }

            if (res.ok) {
                if (editingRuleId === ruleId) cancelEdit();
                loadActiveRules();
            } else {
                const data = await safeParseJson(res);
                alert(data.message || 'Kural silinemedi.');
            }
        } catch (err) {
            alert('Bağlantı hatası: ' + err.message);
        }
    }

    function startEditRule(rule) {
        const def = rule.definition;
        if (!def) return;

        ruleIdInput.value = def.ruleId;
        ruleIdInput.disabled = true; // Düzenleme sırasında RuleId değiştirilemez
        document.getElementById('ruleName').value = def.name || '';
        document.getElementById('ruleDesc').value = def.description || '';
        document.getElementById('targetProperty').value = def.targetProperty || 'UserAccountControl';
        document.getElementById('operator').value = def.operator || 'BitwiseAND';
        document.getElementById('ruleValue').value = def.value ?? '';
        document.getElementById('condition').value = def.condition || 'NotEqualZero';
        document.getElementById('riskLevel').value = def.riskLevel || 'Medium';
        document.getElementById('remediation').value = def.remediation || '';

        editingRuleId = def.ruleId;
        nocodeSubmitBtn.textContent = 'Kuralı Güncelle';
        nocodeCancelEditBtn.classList.remove('hidden');
        nocodeAlert.classList.add('hidden');

        document.querySelector('.tab-btn[data-tab="nocodeTab"]').click();
    }

    function cancelEdit() {
        editingRuleId = null;
        noCodeRuleForm.reset();
        ruleIdInput.disabled = false;
        nocodeSubmitBtn.textContent = 'No-Code Kuralı Kaydet & Aktifleştir';
        nocodeCancelEditBtn.classList.add('hidden');
    }

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
            // "Informational" (örn. SYSVOL/GPO verisi okunamadığı için kural hiç
            // çalıştırılamadı) durumu "GÜVENLİ" ile karıştırılmamalı - kontrol
            // edilemeyen bir şey "güvenli" demek değildir.
            const isInformational = rule.riskLevel === 'Informational';
            const card = document.createElement('div');
            const riskClass = rule.riskLevel.toLowerCase() + '-risk';

            card.className = `vuln-card ${isVuln || isInformational ? riskClass : 'low-risk'}`;

            let affectedHtml = '';
            if (isVuln && rule.affectedObjects) {
                affectedHtml = '<div class="affected-list">' +
                    rule.affectedObjects.map(obj => `<span class="tag-affected">${obj}</span>`).join('') +
                    '</div>';
            }

            // Otomatik Compliance Mapping: sadece gerçek bir zafiyet bulunduğunda gösterilir -
            // "Informational"/güvenli sonuçlarda hangi çerçeveye eşlendiği önemli değildir.
            let complianceHtml = '';
            if (isVuln && (rule.frameworkMapping || rule.iso27001Mapping)) {
                complianceHtml = '<div class="compliance-mapping">' +
                    (rule.frameworkMapping ? `<span class="tag-compliance">${rule.frameworkMapping}</span>` : '') +
                    (rule.iso27001Mapping ? `<span class="tag-compliance">${rule.iso27001Mapping}</span>` : '') +
                    '</div>';
            }

            let statusBadge;
            if (isInformational) {
                statusBadge = 'KONTROL EDİLEMEDİ (Veri Sağlanamadı)';
            } else if (isVuln) {
                statusBadge = 'ZAFİYET BULUNDU (' + rule.riskLevel + ')';
            } else {
                statusBadge = 'GÜVENLİ';
            }

            card.innerHTML = `
                <div class="vuln-header">
                    <span class="vuln-title">${rule.ruleId} - ${rule.name || rule.ruleId}</span>
                    <span class="badge badge-risk-${rule.riskLevel.toLowerCase()}">${statusBadge}</span>
                </div>
                ${affectedHtml}
                ${complianceHtml}
                ${isVuln ? `<div class="remediation-box"><strong>💡 Çözüm Önerisi:</strong><br>${rule.remediation}</div>` : ''}
            `;

            reportsList.appendChild(card);
        });
    }

    // AKTİF KURALLARI YÜKLE (sabit C# kuralları + No-Code JSON kuralları birlikte)
    async function loadActiveRules() {
        activeRulesList.innerHTML = '<p>Kurallar yükleniyor...</p>';
        try {
            const res = await fetch(`${API_BASE}/rules`, {
                headers: { 'Authorization': `Bearer ${jwtToken}` }
            });

            if (res.status === 401) {
                handleUnauthorized();
                return;
            }

            const rules = await safeParseJson(res);
            currentRulesCache = Array.isArray(rules) ? rules : [];

            activeRulesList.innerHTML = '';

            if (currentRulesCache.length === 0) {
                activeRulesList.innerHTML = '<p>Henüz hiç kural yüklenmedi.</p>';
                return;
            }

            currentRulesCache.forEach(r => {
                const item = document.createElement('div');
                item.className = 'vuln-card low-risk';

                const sourceBadge = r.source === 'Static'
                    ? '<span class="badge badge-risk-low">Sabit Kod (C#)</span>'
                    : '<span class="badge badge-risk-low">No-Code (JSON)</span>';

                let actionsHtml = '';
                if (r.source === 'JsonFile') {
                    if (r.isEditable) {
                        actionsHtml += `<button type="button" class="btn btn-sm btn-outline" data-action="edit" data-rule-id="${r.ruleId}">Düzenle</button> `;
                    } else {
                        actionsHtml += `<span style="color:#94a3b8; font-size:12px; margin-right:8px;">Gelişmiş (nested) kural - sadece silinebilir</span>`;
                    }
                    actionsHtml += `<button type="button" class="btn btn-sm btn-outline" data-action="delete" data-rule-id="${r.ruleId}">Sil</button>`;
                }

                const ruleComplianceHtml = (r.frameworkMapping || r.iso27001Mapping)
                    ? '<div class="compliance-mapping">' +
                        (r.frameworkMapping ? `<span class="tag-compliance">${r.frameworkMapping}</span>` : '') +
                        (r.iso27001Mapping ? `<span class="tag-compliance">${r.iso27001Mapping}</span>` : '') +
                        '</div>'
                    : '';

                item.innerHTML = `
                    <div class="vuln-header">
                        <span class="vuln-title">${r.ruleId} - ${r.name}</span>
                        ${sourceBadge}
                    </div>
                    <p style="color: #94a3b8; font-size: 13px;">${r.description}</p>
                    ${ruleComplianceHtml}
                    ${actionsHtml ? `<div class="rule-actions" style="margin-top:10px;">${actionsHtml}</div>` : ''}
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
