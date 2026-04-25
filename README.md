# VT_SHIELD V1.1

Extensao Chromium para verificacao de URLs via VirusTotal API.

## Instalacao (Modo Desenvolvedor)

1. Abra o Chrome/Edge e acesse `chrome://extensions/`
2. Ative o **Modo do desenvolvedor** (cant superior direito)
3. Clique em **Carregar sem compactacao**
4. Selecione a pasta `src/` deste projeto

## Configuracao

1. Clique no icone da extensao e depois em **OPEN SYSTEM_CONFIG**
2. Insira sua API Key do VirusTotal (obtenha em https://www.virustotal.com/gui/join-us)
3. Clique em **Validate & Save**

## Uso

Clique direito em qualquer link ou texto selecionado com URL. Agora o menu VT_SHIELD tem **duas opcoes**:

### Verificacao Simplificada
- Abre um **modal inline** na propria pagina (sem janela nova)
- Mostra apenas: URL, status **SEGURO / MALICIOSO**, e contagem **X/70 engines**
- Tematica hacker minimalista com scanlines e glow
- Fecha com ESC ou clicando fora

### Verificacao Detalhada
- Abre popup em nova janela com **relatorio completo**
- Lista de engines, metricas de reputacao, terminal log, JSON bruto

## Estrutura

- `manifest.json` - Manifesto MV3
- `background.js` - Service worker (context menu + proxy CORS para API)
- `options.html/js` - Tela de configuracao da API key
- `scan.html/js` - Modal detalhado em nova janela
- `content.js/css` - Modal simplificado injetado na pagina atual
- `popup.html` - Popup rapido da extensao
- `styles.css` - Estilos tema hacker (verde #00FF41 + preto)
- `icons/` - Icones gerados da extensao

## API VirusTotal

Documentacao:
- https://docs.virustotal.com/reference/url-info
- https://docs.virustotal.com/reference/url#url-identifiers

## Logica de Seguranca

- `malicious >= 1` ou `suspicious >= 1` -> **MALICIOUS** (vermelho)
- `malicious == 0` e `suspicious == 0` -> **SECURE** (verde)
