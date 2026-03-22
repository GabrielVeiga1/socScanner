# 🛡️ SOC URL Scanner — Extensão Chrome/Firefox

Extensão de segurança voltada para times de **SOC** e **CTI**, permitindo a análise completa de URLs diretamente no navegador, com foco em agilidade na triagem de indicadores (IOCs).

---

## 🚀 Visão Geral

O **SOC URL Scanner** foi desenvolvido para reduzir o tempo de investigação manual, centralizando múltiplas análises em uma única interface.

Ideal para analistas que precisam validar rapidamente a postura de segurança de um domínio durante atividades de **Threat Hunting**, **Incident Response** ou **triagem de alertas**.

---

## 🔍 Funcionalidades

### 🌐 Análise Web
- Headers HTTP de segurança:
  - CSP *(Content-Security-Policy)*
  - HSTS *(Strict-Transport-Security)*
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Identificação de configurações inseguras e ausência de headers críticos

### 🔐 SSL/TLS
- Avaliação de certificado via SSL Labs
- Classificação automática (A → F)
- Detecção de problemas comuns de configuração TLS

### 🌍 DNS & Infraestrutura
- Consulta de registros:
  - A, MX, TXT, NS, CNAME
- Mapeamento básico da infraestrutura do domínio

### 🧠 Enumeração
- Descoberta de subdomínios comuns *(wordlist-based)*
- Identificação de superfícies expostas

### 🚪 Portas e Serviços
- Verificação de portas comuns:
  - HTTP, HTTPS, SSH, FTP, RDP, entre outras
- Detecção baseada em requisições (sem varredura ativa invasiva)

### ⚙️ Fingerprinting Tecnológico
- Identificação de:
  - Servidores web
  - Frameworks
  - CMS
  - CDNs
  - Provedores cloud

### 🤖 Análise com IA (Claude)
- Geração de relatório automatizado contendo:
  - Priorização de riscos
  - Contexto técnico
  - Recomendações de mitigação
- Foco em uso prático para analistas

---

## 🧩 Instalação

### Google Chrome

1. Acesse: `chrome://extensions/`
2. Ative o **Modo do desenvolvedor**
3. Clique em **Carregar sem compactação**
4. Selecione a pasta `soc-scanner`
5. A extensão será carregada na barra 🛡️

---

### Mozilla Firefox

1. Acesse: `about:debugging#/runtime/this-firefox`
2. Clique em **Carregar extensão temporária...**
3. Selecione o arquivo `manifest.json` dentro da pasta `soc-scanner`

---

## 🤖 Configuração da IA

1. Clique no ícone ⚙️ da extensão  
2. Insira sua **Groq API Key**  
3. Salve a chave  
4. Execute um scan e acesse a aba **IA 🤖**  
5. Clique em **Analisar com IA**

🔗 Obtenha sua chave: console.groq.com

---

## 📊 Score de Segurança

| Score  | Nota | Interpretação |
|--------|------|--------------|
| 85–100 | A    | Boa postura de segurança |
| 70–84  | B    | Melhorias recomendadas |
| 50–69  | C    | Configuração incompleta |
| 0–49   | F    | Alto risco / falhas críticas |

---

## ⚠️ Limitações

- A análise de portas é **não-invasiva** (baseada em `fetch`), podendo gerar falsos negativos  
- O SSL Labs pode retornar status **PENDING** — reexecute após alguns minutos  
- Não substitui ferramentas como:
  - Nmap  
  - Burp Suite  
  - Nessus  

---

## 🔒 Privacidade

- Nenhuma URL ou dado analisado é armazenado externamente  
- Todas as análises são realizadas sob demanda pelo usuário  

---

## 💡 Possíveis Evoluções

- Integração com APIs de Threat Intelligence (VirusTotal, AbuseIPDB, Shodan)  
- Exportação de relatórios (JSON / PDF)  
- Histórico local de análises  
- Integração com SIEM (Splunk, ELK)  
