let scanData = {};

function updateKeyWrapVisibility() {}

document.addEventListener('DOMContentLoaded', async () => {
  const stored = await chrome.storage.local.get(['groqKey']);
  if (stored.groqKey) document.getElementById('groqKeyInput').value = stored.groqKey;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url && tab.url.startsWith('http')) {
    document.getElementById('urlInput').value = tab.url;
  }

  document.getElementById('settingsToggle').addEventListener('click', () => {
    document.getElementById('settingsPanel').classList.toggle('open');
  });

  document.getElementById('saveApiKey').addEventListener('click', async () => {
    const groqKey = document.getElementById('groqKeyInput').value.trim();
    await chrome.storage.local.set({ groqKey });
    document.getElementById('saveApiKey').textContent = 'Salvo ✓';
    setTimeout(() => document.getElementById('saveApiKey').textContent = 'Salvar', 1500);
  });

  document.getElementById('scanBtn').addEventListener('click', startScan);
  document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') startScan();
  });

  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('panel-' + tab.dataset.tab).classList.add('active');
    });
  });
});

async function startScan() {
  let url = document.getElementById('urlInput').value.trim();
  if (!url) return;
  if (!url.startsWith('http')) url = 'https://' + url;

  let hostname;
  try { hostname = new URL(url).hostname; }
  catch { alert('URL inválida'); return; }

  document.getElementById('scanBtn').disabled = true;
  document.getElementById('scanBtn').textContent = 'Escaneando...';
  document.getElementById('results').classList.remove('active');
  document.getElementById('progressWrap').classList.add('active');

  resetSteps();
  scanData = { url, hostname };

  try {
    setStep('step-headers', 'active');
    const headerData = await chrome.runtime.sendMessage({ action: 'analyzeHeaders', url });
    scanData.headers = headerData;
    setStep('step-headers', 'done');

    setStep('step-ssl', 'active');
    const sslData = await Scanner.checkSSL(hostname);
    scanData.ssl = sslData;
    setStep('step-ssl', 'done');

    setStep('step-dns', 'active');
    const dnsData = await Scanner.checkDNS(hostname);
    scanData.dns = dnsData;
    setStep('step-dns', 'done');

    setStep('step-ports', 'active');
    const portData = await Scanner.checkPorts(hostname);
    scanData.ports = portData;
    setStep('step-ports', 'done');

    setStep('step-done', 'active');
    if (headerData.success) {
      scanData.techs = Scanner.detectTechnologies(headerData.allHeaders);
      const scored = Scanner.scoreHeaders(headerData.security);
      scanData.score = scored.score;
      scanData.issues = scored.issues;
    } else {
      scanData.techs = [];
      scanData.score = 0;
      scanData.issues = [{ level: 'high', msg: 'Não foi possível conectar: ' + (headerData.error || 'erro desconhecido') }];
    }
    setStep('step-done', 'done');

    await new Promise(r => setTimeout(r, 300));
    document.getElementById('progressWrap').classList.remove('active');
    renderResults();
    document.getElementById('results').classList.add('active');
  } catch (err) {
    document.getElementById('progressWrap').classList.remove('active');
    alert('Erro durante o scan: ' + err.message);
  }

  document.getElementById('scanBtn').disabled = false;
  document.getElementById('scanBtn').textContent = 'Escanear';
}

function setStep(id, state) {
  const el = document.getElementById(id);
  el.classList.remove('active', 'done');
  const labels = { 'step-headers': 'Analisando headers HTTP...', 'step-ssl': 'Verificando certificado SSL...', 'step-dns': 'Consultando registros DNS...', 'step-ports': 'Detectando portas abertas...', 'step-done': 'Consolidando resultados...' };
  const doneLabels = { 'step-headers': 'Headers HTTP analisados', 'step-ssl': 'SSL verificado', 'step-dns': 'DNS consultado', 'step-ports': 'Portas verificadas', 'step-done': 'Concluído!' };
  if (state === 'active') {
    el.classList.add('active');
    el.innerHTML = `<span class="step-icon"><span class="spinner"></span></span> ${labels[id]}`;
  } else if (state === 'done') {
    el.classList.add('done');
    el.innerHTML = `<span class="step-icon">✓</span> ${doneLabels[id]}`;
  }
}

function resetSteps() {
  const labels = { 'step-headers': 'Analisando headers HTTP...', 'step-ssl': 'Verificando certificado SSL...', 'step-dns': 'Consultando registros DNS...', 'step-ports': 'Detectando portas abertas...', 'step-done': 'Consolidando resultados...' };
  Object.entries(labels).forEach(([id, label]) => {
    document.getElementById(id).classList.remove('active','done');
    document.getElementById(id).innerHTML = `<span class="step-icon">⏳</span> ${label}`;
  });
}

function renderResults() {
  renderScore(); renderIssues(); renderHeaders(); renderTech(); renderSSL(); renderDNS(); renderPorts(); renderAI();
}

function renderScore() {
  const score = scanData.score || 0;
  const circle = document.getElementById('scoreCircle');
  const bar = document.getElementById('scoreBar');
  const label = document.getElementById('scoreLabel');
  circle.textContent = score;
  bar.style.width = score + '%';
  let cls, color;
  if (score >= 85) { cls = 'score-a'; color = 'var(--green)'; }
  else if (score >= 70) { cls = 'score-b'; color = 'var(--yellow)'; }
  else if (score >= 50) { cls = 'score-c'; color = 'var(--orange)'; }
  else { cls = 'score-f'; color = 'var(--red)'; }
  circle.className = 'score-circle ' + cls;
  bar.style.background = color;
  label.textContent = `${scanData.hostname} — Score ${score}/100`;
}

function renderIssues() {
  const issues = scanData.issues || [];
  document.getElementById('cnt-issues').textContent = issues.length;
  const panel = document.getElementById('panel-issues');
  if (!issues.length) { panel.innerHTML = '<div class="empty-state">✅ Nenhum problema detectado!</div>'; return; }
  panel.innerHTML = issues.sort((a,b) => ({high:0,medium:1,low:2}[a.level] - {high:0,medium:1,low:2}[b.level]))
    .map(i => `<div class="issue-row"><span class="issue-badge issue-${i.level}">${i.level==='high'?'ALTO':i.level==='medium'?'MÉDIO':'BAIXO'}</span><span>${i.msg}</span></div>`).join('');
}

function renderHeaders() {
  const sec = scanData.headers?.security || {};
  const present = Object.values(sec).filter(h => h.present).length;
  const total = Object.values(sec).length;
  document.getElementById('cnt-headers').textContent = `${present}/${total}`;
  const panel = document.getElementById('panel-headers');
  let html = '<div class="section-title">Headers de Segurança</div>';
  for (const [, h] of Object.entries(sec)) {
    html += `<div class="header-row">
      <span class="hdr-status"><span class="dot ${h.present ? 'dot-ok' : h.critical ? 'dot-err' : 'dot-warn'}"></span></span>
      <span class="hdr-name">${h.label}</span>
      ${h.present ? `<span class="hdr-value">${escHtml(h.value)}</span>` : `<span class="hdr-missing">${h.critical ? '✗ Ausente (crítico)' : '✗ Ausente'}</span>`}
    </div>`;
  }
  const allH = scanData.headers?.allHeaders || {};
  const infoH = ['server','x-powered-by','via','x-aspnet-version'].filter(k => allH[k]);
  if (infoH.length) {
    html += '<div class="section-title" style="margin-top:14px">Exposição de informações</div>';
    infoH.forEach(k => { html += `<div class="header-row"><span class="hdr-status"><span class="dot dot-warn"></span></span><span class="hdr-name">${k}</span><span class="hdr-value">${escHtml(allH[k])}</span></div>`; });
  }
  panel.innerHTML = html;
}

function renderTech() {
  const techs = scanData.techs || [];
  document.getElementById('cnt-tech').textContent = techs.length;
  const panel = document.getElementById('panel-tech');
  if (!techs.length) { panel.innerHTML = '<div class="empty-state">Nenhuma tecnologia detectada via headers.</div>'; return; }
  const catColors = { server:'var(--blue)', framework:'var(--yellow)', language:'var(--green)', cms:'var(--orange)', cdn:'#a78bfa', cloud:'var(--green)' };
  panel.innerHTML = `<div class="section-title">Tecnologias Detectadas</div><div class="tech-grid">${
    techs.map(t => `<div class="tech-card"><div class="tech-name">${escHtml(t.name)}</div><div class="tech-cat" style="color:${catColors[t.category]||'var(--muted)'}">${t.category}</div>${t.value?`<div class="tech-val">${escHtml(t.value)}</div>`:''}</div>`).join('')
  }</div>`;
}

function renderSSL() {
  const ssl = scanData.ssl || {};
  const grade = ssl.grade || 'N/A';
  const cls = grade.startsWith('A') ? 'ssl-a' : grade === 'B' ? 'ssl-b' : grade === 'C' ? 'ssl-c' : grade === 'F' ? 'ssl-f' : 'ssl-na';
  document.getElementById('panel-ssl').innerHTML = `
    <div style="text-align:center;padding:12px 0 8px">
      <div class="ssl-grade ${cls}">${grade}</div>
      <div style="font-size:13px;color:var(--muted)">${escHtml(ssl.details || 'Verificação via SSL Labs')}</div>
      ${ssl.hasWarnings ? '<div style="margin-top:6px;font-size:12px;color:var(--orange)">⚠️ Avisos detectados</div>' : ''}
    </div>
    <div style="margin-top:10px;padding:10px;background:var(--bg3);border-radius:6px;font-size:12px;color:var(--muted);line-height:1.6">
      Nota fornecida via <strong style="color:var(--text)">SSL Labs API</strong>. Se retornar PENDING, aguarde 1 min e re-escaneie.
    </div>`;
}

function renderDNS() {
  const dns = scanData.dns || { records: [], subdomains: [] };
  document.getElementById('cnt-dns').textContent = dns.records.length + dns.subdomains.length;
  const panel = document.getElementById('panel-dns');
  let html = '<div class="section-title">Registros DNS</div>';
  if (!dns.records.length) { html += '<div class="empty-state">Nenhum registro encontrado.</div>'; }
  else { dns.records.forEach(r => { html += `<div class="dns-record"><span class="dns-type">${r.type}</span><span class="dns-data">${r.data.map(escHtml).join('<br>')}</span></div>`; }); }
  html += '<div class="section-title" style="margin-top:14px">Subdomínios Descobertos</div>';
  if (!dns.subdomains.length) { html += '<div style="font-size:12px;color:var(--muted);padding:4px 0">Nenhum subdomínio comum encontrado.</div>'; }
  else { html += `<div class="subdomain-list">${dns.subdomains.map(s => `<span class="subdomain-tag">${escHtml(s)}</span>`).join('')}</div>`; }
  panel.innerHTML = html;
}

function renderPorts() {
  const ports = scanData.ports || [];
  document.getElementById('cnt-ports').textContent = ports.length;
  const panel = document.getElementById('panel-ports');
  const risky = [21, 23, 3389];
  if (!ports.length) { panel.innerHTML = '<div class="empty-state">Nenhuma porta detectada como acessível.</div>'; return; }
  panel.innerHTML = `
    <div class="section-title">Portas Acessíveis</div>
    <div class="port-grid">${ports.map(p => `
      <div class="port-card ${risky.includes(p.port)?'port-open':''}">
        <div class="port-num ${risky.includes(p.port)?'port-num-open':''}">${p.port}</div>
        <div class="port-svc">${p.service}</div>
        ${risky.includes(p.port)?'<div style="font-size:10px;color:var(--red);margin-top:3px">⚠️ Risco</div>':''}
      </div>`).join('')}
    </div>
    ${ports.some(p=>risky.includes(p.port))?'<div style="margin-top:10px;padding:8px 10px;background:rgba(224,82,82,0.08);border:1px solid rgba(224,82,82,0.2);border-radius:6px;font-size:12px;color:var(--red)">Portas de risco detectadas.</div>':''}`;
}

function renderAI() {
  document.getElementById('panel-ai').innerHTML = `
    <div style="margin-bottom:10px;font-size:12px;color:var(--muted);line-height:1.6">
      Análise completa com LLaMA 3.3 70B via Groq — riscos priorizados e remediações em português.
    </div>
    <button class="ai-btn" id="aiAnalyzeBtn">🤖 Analisar com IA</button>
    <div id="aiOutput"></div>`;
  document.getElementById('aiAnalyzeBtn').addEventListener('click', runAIAnalysis);
}

async function runAIAnalysis() {
  const stored = await chrome.storage.local.get(['groqKey']);
  if (!stored.groqKey) {
    document.getElementById('aiOutput').innerHTML = `<div style="color:var(--red);font-size:12px">Configure sua Groq API Key nas configurações (⚙️). Gratuito em <a href="https://console.groq.com/keys" style="color:var(--yellow)">console.groq.com</a></div>`;
    return;
  }
  document.getElementById('aiAnalyzeBtn').disabled = true;
  document.getElementById('aiOutput').innerHTML = `<div class="ai-loading"><span class="spinner"></span> Analisando com LLaMA 3.3...</div>`;

  const sec = scanData.headers?.security || {};
  const missing = Object.values(sec).filter(h => !h.present).map(h => h.label);
  const present = Object.values(sec).filter(h => h.present).map(h => h.label);

  const prompt = `Você é um especialista em segurança web e analista de SOC da empresa DropReal Cybersecurity & Compliance. Analise os dados abaixo e gere um relatório em português com: 1) Resumo executivo dos riscos, 2) Problemas priorizados por criticidade, 3) Recomendações de remediação objetivas.

URL: ${scanData.url}
Score de segurança: ${scanData.score}/100
Headers presentes: ${present.join(', ') || 'nenhum'}
Headers ausentes: ${missing.join(', ') || 'nenhum'}
Tecnologias: ${(scanData.techs||[]).map(t=>`${t.name}(${t.category})`).join(', ')||'nenhuma'}
SSL Grade: ${scanData.ssl?.grade||'N/A'} — ${scanData.ssl?.details||''}
DNS: ${(scanData.dns?.records||[]).map(r=>`${r.type}:${r.data.join(',')}`).join(' | ')||'nenhum'}
Subdomínios: ${(scanData.dns?.subdomains||[]).join(', ')||'nenhum'}
Portas: ${(scanData.ports||[]).map(p=>`${p.port}/${p.service}`).join(', ')||'nenhuma'}
Problemas: ${(scanData.issues||[]).map(i=>`[${i.level.toUpperCase()}] ${i.msg}`).join('; ')||'nenhum'}

Seja direto e técnico. Use seções claras.`;

  const result = await chrome.runtime.sendMessage({ action: 'callGroq', apiKey: stored.groqKey, prompt });

  if (result.success) {
    document.getElementById('aiOutput').innerHTML = `<div class="ai-box">${escHtml(result.text)}</div>`;
  } else {
    document.getElementById('aiOutput').innerHTML = `<div style="color:var(--red);font-size:12px">Erro: ${escHtml(result.error)}</div>`;
  }
  document.getElementById('aiAnalyzeBtn').disabled = false;
}

function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
