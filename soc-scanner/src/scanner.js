const Scanner = {
  async checkSSL(hostname) {
    try {
      const res = await fetch(`https://api.ssllabs.com/api/v3/analyze?host=${hostname}&startNew=off&fromCache=on&ignoreMismatch=on`, {
        signal: AbortSignal.timeout(8000)
      });
      const data = await res.json();
      if (data.status === 'READY' && data.endpoints?.length > 0) {
        const ep = data.endpoints[0];
        return {
          grade: ep.grade || '?',
          hasWarnings: ep.hasWarnings,
          isExceptional: ep.isExceptional,
          details: ep.statusMessage
        };
      }
      return { grade: data.status === 'ERROR' ? 'ERR' : 'PENDING', details: data.statusMessage || 'Análise em andamento' };
    } catch {
      return { grade: 'N/A', details: 'SSL Labs indisponível' };
    }
  },

  async checkDNS(hostname) {
    const results = { records: [], subdomains: [] };
    try {
      const types = ['A', 'MX', 'TXT', 'NS', 'CNAME'];
      const promises = types.map(async (type) => {
        try {
          const r = await fetch(`https://dns.google/resolve?name=${hostname}&type=${type}`, { signal: AbortSignal.timeout(5000) });
          const d = await r.json();
          if (d.Answer?.length > 0) {
            results.records.push({ type, data: d.Answer.map(a => a.data).slice(0, 3) });
          }
        } catch {}
      });
      await Promise.all(promises);

      const commonSubs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test', 'vpn', 'remote', 'webmail', 'portal', 'app'];
      const subChecks = await Promise.allSettled(
        commonSubs.map(async (sub) => {
          try {
            const r = await fetch(`https://dns.google/resolve?name=${sub}.${hostname}&type=A`, { signal: AbortSignal.timeout(3000) });
            const d = await r.json();
            if (d.Answer?.length > 0) return `${sub}.${hostname}`;
          } catch {}
          return null;
        })
      );
      results.subdomains = subChecks.filter(r => r.status === 'fulfilled' && r.value).map(r => r.value);
    } catch {}
    return results;
  },

  async checkPorts(hostname) {
    const commonPorts = [
      { port: 21, service: 'FTP' },
      { port: 22, service: 'SSH' },
      { port: 23, service: 'Telnet' },
      { port: 25, service: 'SMTP' },
      { port: 80, service: 'HTTP' },
      { port: 443, service: 'HTTPS' },
      { port: 3389, service: 'RDP' },
      { port: 8080, service: 'HTTP Alt' },
      { port: 8443, service: 'HTTPS Alt' }
    ];

    const results = [];
    await Promise.allSettled(
      commonPorts.map(async ({ port, service }) => {
        try {
          const url = port === 443 || port === 8443
            ? `https://${hostname}:${port}`
            : `http://${hostname}:${port}`;
          const r = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(2500), mode: 'no-cors' });
          results.push({ port, service, open: true, status: r.status || 'open' });
        } catch (e) {
          if (!e.message.includes('abort') && !e.message.includes('timeout')) {
            results.push({ port, service, open: true, status: 'responded' });
          }
        }
      })
    );
    return results;
  },

  detectTechnologies(headers, bodySnippet = '') {
    const techs = [];
    const h = headers || {};

    if (h['x-powered-by']) {
      const xpb = h['x-powered-by'].toLowerCase();
      if (xpb.includes('php')) techs.push({ name: 'PHP', category: 'language', value: h['x-powered-by'] });
      if (xpb.includes('asp')) techs.push({ name: 'ASP.NET', category: 'framework', value: h['x-powered-by'] });
      if (xpb.includes('express')) techs.push({ name: 'Express.js', category: 'framework', value: h['x-powered-by'] });
      if (xpb.includes('next')) techs.push({ name: 'Next.js', category: 'framework', value: h['x-powered-by'] });
    }
    if (h['server']) {
      const srv = h['server'].toLowerCase();
      if (srv.includes('nginx')) techs.push({ name: 'Nginx', category: 'server', value: h['server'] });
      if (srv.includes('apache')) techs.push({ name: 'Apache', category: 'server', value: h['server'] });
      if (srv.includes('iis')) techs.push({ name: 'IIS', category: 'server', value: h['server'] });
      if (srv.includes('litespeed')) techs.push({ name: 'LiteSpeed', category: 'server', value: h['server'] });
      if (srv.includes('cloudflare')) techs.push({ name: 'Cloudflare', category: 'cdn', value: h['server'] });
    }
    if (h['cf-ray']) techs.push({ name: 'Cloudflare', category: 'cdn', value: 'CDN/WAF' });
    if (h['x-amz-request-id'] || h['x-amz-id-2']) techs.push({ name: 'AWS', category: 'cloud', value: 'Amazon Web Services' });
    if (h['x-azure-ref']) techs.push({ name: 'Azure', category: 'cloud', value: 'Microsoft Azure' });
    if (h['x-goog-backend-server'] || h['server']?.includes('gws')) techs.push({ name: 'Google Cloud', category: 'cloud', value: 'GCP' });
    if (h['x-wp-total'] || h['x-wp-totalpages']) techs.push({ name: 'WordPress', category: 'cms', value: 'WordPress REST API' });
    if (h['x-drupal-cache']) techs.push({ name: 'Drupal', category: 'cms', value: 'Drupal' });
    if (h['set-cookie']?.includes('PHPSESSID')) techs.push({ name: 'PHP Session', category: 'language', value: 'PHP' });
    if (h['set-cookie']?.includes('laravel')) techs.push({ name: 'Laravel', category: 'framework', value: 'Laravel' });

    return [...new Map(techs.map(t => [t.name, t])).values()];
  },

  scoreHeaders(security) {
    let score = 100;
    let issues = [];
    const checks = Object.values(security);
    const critical = checks.filter(c => c.critical && !c.present);
    const minor = checks.filter(c => !c.critical && !c.present);
    score -= critical.length * 15;
    score -= minor.length * 5;
    critical.forEach(c => issues.push({ level: 'high', msg: `${c.label} ausente` }));
    minor.forEach(c => issues.push({ level: 'medium', msg: `${c.label} ausente` }));

    if (security['x-powered-by']?.present) issues.push({ level: 'medium', msg: 'Tecnologia exposta via X-Powered-By' });
    if (security['server']?.present) issues.push({ level: 'low', msg: 'Versão do servidor exposta no header Server' });

    return { score: Math.max(0, score), issues };
  }
};

window.Scanner = Scanner;
