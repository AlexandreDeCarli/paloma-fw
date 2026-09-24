// Paloma Shield Dashboard Client App
(function() {
  'use strict';

  // State
  let isAuthenticated = false;
  let refreshTimer = null;
  let currentTargetUnbanIP = null;
  let eventsPage = 1;
  const eventsLimit = 20;

  // DOM Elements
  const loginView = document.getElementById('login-view');
  const dashboardView = document.getElementById('dashboard-view');
  const loginForm = document.getElementById('login-form');
  const passwordInput = document.getElementById('admin-password');
  const togglePasswordBtn = document.getElementById('toggle-password');
  const loginError = document.getElementById('login-error');
  const loginBtn = document.getElementById('login-button');
  const btnLogout = document.getElementById('btn-logout');
  const btnManualRefresh = document.getElementById('btn-manual-refresh');
  const refreshRateSelect = document.getElementById('refresh-rate');

  // Stats
  const statActiveBans = document.getElementById('stat-active-bans');
  const statBans24h = document.getElementById('stat-bans-24h');
  const statTotalBans = document.getElementById('stat-total-bans');
  const statTotalUnbans = document.getElementById('stat-total-unbans');
  const activeCountBadge = document.getElementById('active-count-badge');
  const activeBansBody = document.getElementById('active-bans-body');

  // Events Table & Filters
  const eventsBody = document.getElementById('events-body');
  const filterIP = document.getElementById('filter-ip');
  const filterType = document.getElementById('filter-type');
  const paginationInfo = document.getElementById('pagination-info');
  const btnPrevPage = document.getElementById('btn-prev-page');
  const btnNextPage = document.getElementById('btn-next-page');

  // Modal
  const unbanModal = document.getElementById('unban-modal');
  const modalTargetIP = document.getElementById('modal-target-ip');
  const modalNotes = document.getElementById('modal-notes');
  const modalCancelBtn = document.getElementById('modal-cancel-btn');
  const modalCloseBtn = document.getElementById('modal-close-btn');
  const modalConfirmBtn = document.getElementById('modal-confirm-btn');

  // Initialize
  document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    checkAuth();
  });

  function setupEventListeners() {
    // Password toggle
    if (togglePasswordBtn && passwordInput) {
      togglePasswordBtn.addEventListener('click', () => {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        togglePasswordBtn.textContent = type === 'password' ? '👁️' : '🔒';
      });
    }

    // Login submit
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await handleLogin();
      });
    }

    // Logout
    if (btnLogout) {
      btnLogout.addEventListener('click', async () => {
        await handleLogout();
      });
    }

    // Refresh controls
    if (btnManualRefresh) {
      btnManualRefresh.addEventListener('click', () => {
        refreshAllData();
      });
    }

    if (refreshRateSelect) {
      refreshRateSelect.addEventListener('change', () => {
        setupAutoRefresh();
      });
    }

    // Filters
    let debounceTimer;
    if (filterIP) {
      filterIP.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          eventsPage = 1;
          fetchEvents();
        }, 300);
      });
    }

    if (filterType) {
      filterType.addEventListener('change', () => {
        eventsPage = 1;
        fetchEvents();
      });
    }

    // Pagination
    if (btnPrevPage) {
      btnPrevPage.addEventListener('click', () => {
        if (eventsPage > 1) {
          eventsPage--;
          fetchEvents();
        }
      });
    }

    if (btnNextPage) {
      btnNextPage.addEventListener('click', () => {
        eventsPage++;
        fetchEvents();
      });
    }

    // Modal controls
    if (modalCancelBtn) modalCancelBtn.addEventListener('click', closeModal);
    const closeBtn = document.getElementById('modal-close-btn') || document.getElementById('modal-close');
    if (closeBtn) closeBtn.addEventListener('click', closeModal);
    if (unbanModal) {
      unbanModal.addEventListener('click', (e) => {
        if (e.target === unbanModal) closeModal();
      });
    }
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && unbanModal && unbanModal.style.display !== 'none') {
        closeModal();
      }
    });

    if (modalConfirmBtn) {
      modalConfirmBtn.addEventListener('click', async () => {
        await executeUnban();
      });
    }
  }

  async function checkAuth() {
    try {
      const res = await fetch('/api/auth/check');
      const data = await res.json();
      if (data.authenticated) {
        setAuthenticatedState(true);
      } else {
        setAuthenticatedState(false);
      }
    } catch {
      setAuthenticatedState(false);
    }
  }

  function setAuthenticatedState(auth) {
    isAuthenticated = auth;
    if (auth) {
      loginView.style.display = 'none';
      dashboardView.style.display = 'flex';
      refreshAllData();
      setupAutoRefresh();
    } else {
      dashboardView.style.display = 'none';
      loginView.style.display = 'flex';
      clearInterval(refreshTimer);
    }
  }

  async function handleLogin() {
    const password = passwordInput.value;
    setLoading(loginBtn, true);
    loginError.style.display = 'none';

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });

      const data = await res.json();
      if (res.ok && data.success) {
        passwordInput.value = '';
        setAuthenticatedState(true);
        showToast('Autenticado com sucesso.', 'success');
      } else {
        loginError.textContent = data.error === 'invalid credentials' ? 'Chave incorreta. Tente novamente.' : 'Erro ao autenticar.';
        loginError.style.display = 'block';
      }
    } catch (err) {
      loginError.textContent = 'Falha de comunicação com o servidor Paloma.';
      loginError.style.display = 'block';
    } finally {
      setLoading(loginBtn, false);
    }
  }

  async function handleLogout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } finally {
      setAuthenticatedState(false);
      showToast('Sessão encerrada.', 'success');
    }
  }

  function setupAutoRefresh() {
    clearInterval(refreshTimer);
    const ms = parseInt(refreshRateSelect.value, 10);
    if (ms > 0 && isAuthenticated) {
      refreshTimer = setInterval(() => {
        refreshAllData(true);
      }, ms);
    }
  }

  async function refreshAllData(silent = false) {
    if (!isAuthenticated) return;
    try {
      await Promise.all([
        fetchMetrics(),
        fetchBans(),
        fetchEvents()
      ]);
      if (!silent) {
        showToast('Dados atualizados com sucesso.', 'success');
      }
    } catch (err) {
      if (!silent) {
        showToast('Falha ao atualizar dados.', 'error');
      }
    }
  }

  async function fetchMetrics() {
    const res = await fetch('/api/metrics');
    if (!res.ok) return;
    const m = await res.json();
    statActiveBans.textContent = m.active_bans_count ?? 0;
    statBans24h.textContent = m.bans_last_24h ?? 0;
    statTotalBans.textContent = m.total_bans_all_time ?? 0;
    statTotalUnbans.textContent = m.total_unbans ?? 0;
  }

  async function fetchBans() {
    const res = await fetch('/api/bans');
    if (!res.ok) return;
    const data = await res.json();
    const active = data.active_bans || [];

    // Fallback: merge any live kernel ban from Fail2ban socket if not in database yet
    const existingIPs = new Set(active.map(b => b.ip));
    if (data.live_status && Array.isArray(data.live_status.banned_ip_list)) {
      for (const ip of data.live_status.banned_ip_list) {
        if (!existingIPs.has(ip)) {
          active.push({
            ip: ip,
            jail: data.live_status.jail || 'traefik-401',
            failures: 15,
            banned_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 172800000).toISOString(),
            status: 'active'
          });
        }
      }
    }

    activeCountBadge.textContent = `${active.length} ${active.length === 1 ? 'ativo' : 'ativos'}`;

    if (active.length === 0) {
      activeBansBody.innerHTML = '<tr><td colspan="6" class="table-empty">Nenhum IP bloqueado no momento. Defesas operando normalmente.</td></tr>';
      return;
    }

    activeBansBody.innerHTML = active.map(b => {
      const bannedAt = new Date(b.banned_at).toLocaleString('pt-BR');
      const expiresAt = new Date(b.expires_at).toLocaleString('pt-BR');
      return `
        <tr>
          <td>
            <div class="ip-cell">
              <span class="ip-text font-mono">${escapeHtml(b.ip)}</span>
              <button class="copy-btn" onclick="copyToClipboard('${escapeHtml(b.ip)}')" title="Copiar IP">📋</button>
            </div>
          </td>
          <td><span class="code-inline">${escapeHtml(b.jail)}</span></td>
          <td><strong>${b.failures}</strong> tentativas</td>
          <td>${bannedAt}</td>
          <td>${expiresAt}</td>
          <td class="text-right">
            <button class="btn btn-danger btn-sm" onclick="openUnbanModal('${escapeHtml(b.ip)}')">
              Desbanir
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  async function fetchEvents() {
    const ip = encodeURIComponent(filterIP.value.trim());
    const type = encodeURIComponent(filterType.value);
    const res = await fetch(`/api/events?page=${eventsPage}&limit=${eventsLimit}&search=${ip}&type=${type}`);
    if (!res.ok) return;
    const data = await res.json();
    const events = data.events || [];
    const total = data.total || 0;

    paginationInfo.textContent = `Página ${eventsPage} • Total de ${total} registros`;
    btnPrevPage.disabled = eventsPage <= 1;
    btnNextPage.disabled = (eventsPage * eventsLimit) >= total;

    if (events.length === 0) {
      eventsBody.innerHTML = '<tr><td colspan="6" class="table-empty">Nenhum evento registrado com os filtros informados.</td></tr>';
      return;
    }

    eventsBody.innerHTML = events.map(e => {
      const createdAt = new Date(e.created_at).toLocaleString('pt-BR');
      let typeBadge = '';
      if (e.event_type === 'ban') {
        typeBadge = '<span class="badge-event badge-ban">Bloqueio</span>';
      } else if (e.event_type === 'manual_unban') {
        typeBadge = '<span class="badge-event badge-manual">Desbloqueio Manual</span>';
      } else {
        typeBadge = '<span class="badge-event badge-unban">Desbloqueio</span>';
      }

      return `
        <tr>
          <td>${typeBadge}</td>
          <td><span class="font-mono font-semibold">${escapeHtml(e.ip)}</span></td>
          <td><span class="code-inline">${escapeHtml(e.jail)}</span></td>
          <td>${escapeHtml(e.reason)}</td>
          <td>${escapeHtml(e.actor)}</td>
          <td>${createdAt}</td>
        </tr>
      `;
    }).join('');
  }

  // Modal & Unban Action
  window.openUnbanModal = function(ip) {
    currentTargetUnbanIP = ip;
    modalTargetIP.textContent = ip;
    modalNotes.value = '';
    unbanModal.style.display = 'flex';
  };

  function closeModal() {
    unbanModal.style.display = 'none';
    currentTargetUnbanIP = null;
  }

  async function executeUnban() {
    if (!currentTargetUnbanIP) return;
    setLoading(modalConfirmBtn, true);

    try {
      const res = await fetch('/api/bans/unban', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: currentTargetUnbanIP,
          jail: 'traefik-401',
          notes: modalNotes.value.trim()
        })
      });

      const data = await res.json();
      if (res.ok && data.success) {
        showToast(`IP ${currentTargetUnbanIP} desbanido com sucesso!`, 'success');
        closeModal();
        await refreshAllData(true);
      } else {
        showToast(`Erro ao desbanir: ${data.error || 'Falha desconhecida'}`, 'error');
      }
    } catch {
      showToast('Erro de comunicação ao executar desbanimento.', 'error');
    } finally {
      setLoading(modalConfirmBtn, false);
    }
  }

  // Helpers
  window.copyToClipboard = function(text) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(`IP ${text} copiado!`, 'success');
    });
  };

  function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<span>${type === 'success' ? '✓' : '⚠️'}</span><span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.2s ease';
      setTimeout(() => toast.remove(), 200);
    }, 3500);
  }

  function setLoading(btn, isLoading) {
    const textSpan = btn.querySelector('.btn-text');
    const spinner = btn.querySelector('.btn-spinner');
    if (isLoading) {
      btn.disabled = true;
      if (textSpan) textSpan.style.opacity = '0.4';
      if (spinner) spinner.style.display = 'inline-block';
    } else {
      btn.disabled = false;
      if (textSpan) textSpan.style.opacity = '1';
      if (spinner) spinner.style.display = 'none';
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag));
  }
})();
