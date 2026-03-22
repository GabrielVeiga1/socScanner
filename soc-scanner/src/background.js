chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeHeaders') {
    analyzeHeaders(request.url).then(sendResponse);
    return true;
  }
  if (request.action === 'callGroq') {
    callGroq(request.apiKey, request.prompt).then(sendResponse);
    return true;
  }
});

async function analyzeHeaders(url) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const res = await fetch(url, { method: 'HEAD', signal: controller.signal, redirect: 'follow' });
    clearTimeout(timeout);
    const headers = {};
    res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
    const securityHeaders = {
      'strict-transport-security': { label: 'HSTS', critical: true },
      'content-security-policy': { label: 'CSP', critical: true },
      'x-frame-options': { label: 'X-Frame-Options', critical: true },
      'x-content-type-options': { label: 'X-Content-Type-Options', critical: false },
      'referrer-policy': { label: 'Referrer-Policy', critical: false },
      'permissions-policy': { label: 'Permissions-Policy', critical: false },
      'x-xss-protection': { label: 'X-XSS-Protection', critical: false },
      'cross-origin-embedder-policy': { label: 'COEP', critical: false },
      'cross-origin-opener-policy': { label: 'COOP', critical: false },
      'cross-origin-resource-policy': { label: 'CORP', critical: false }
    };
    const results = {};
    for (const [header, info] of Object.entries(securityHeaders)) {
      results[header] = { label: info.label, critical: info.critical, present: !!headers[header], value: headers[header] || null };
    }
    const techHeaders = {
      server: headers['server'] || null,
      'x-powered-by': headers['x-powered-by'] || null,
      'x-aspnet-version': headers['x-aspnet-version'] || null,
      'x-generator': headers['x-generator'] || null,
      via: headers['via'] || null,
      'cf-ray': headers['cf-ray'] ? 'Cloudflare' : null,
      'x-amz-request-id': headers['x-amz-request-id'] ? 'AWS' : null,
      'x-azure-ref': headers['x-azure-ref'] ? 'Azure' : null
    };
    return { success: true, status: res.status, finalUrl: res.url, security: results, tech: techHeaders, allHeaders: headers };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

async function callGroq(apiKey, prompt) {
  try {
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: 'Você é um especialista em segurança web e analista de SOC.' },
          { role: 'user', content: prompt }
        ],
        max_tokens: 1024,
        temperature: 0.3
      })
    });
    const data = await res.json();
    if (data.error) return { success: false, error: data.error.message };
    const text = data.choices?.[0]?.message?.content;
    if (!text) return { success: false, error: 'Resposta vazia do Groq' };
    return { success: true, text };
  } catch (e) {
    return { success: false, error: e.message };
  }
}
