// xterm's DOM renderer writes its layout and palette rules into <style>
// elements it creates; the platform edge CSP (style-src 'self' 'nonce-…')
// ignores such elements. Mirroring their text into a constructed stylesheet
// (adoptedStyleSheets, which CSP does not govern) keeps the terminal
// rendered without loosening the policy. Harmless where inline styles are
// allowed: the rules are the same.
export interface StyleMirror {
  sync(): void
  dispose(): void
}

export function mirrorStyles(root: HTMLElement): StyleMirror {
  const supported = typeof CSSStyleSheet !== 'undefined' && 'replaceSync' in CSSStyleSheet.prototype && 'adoptedStyleSheets' in document
  if (!supported) return { sync() {}, dispose() {} }
  const sheet = new CSSStyleSheet()
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet]
  return {
    sync() {
      const css = Array.from(root.querySelectorAll('style'), (s) => s.textContent ?? '').join('\n')
      try {
        sheet.replaceSync(css)
      } catch {
        // not CSS: keep the last good rules
      }
    },
    dispose() {
      document.adoptedStyleSheets = document.adoptedStyleSheets.filter((s) => s !== sheet)
    },
  }
}
