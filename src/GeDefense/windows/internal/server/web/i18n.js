// STATUS: PLATIN VGT SUPREME
// GeDefense Windows UI localization: German (source), English, Russian, Simplified Chinese.
// Runtime translation is DOM-based and additive: untranslated technical strings keep
// their source text. No external requests, no persistent browser storage APIs;
// the manual language choice is stored in a first-party SameSite cookie.
import { TRANSLATIONS } from './i18n-data.js';

export const LANGUAGES = ['de', 'en', 'ru', 'zh'];
export const LANGUAGE_NAMES = { de: 'Deutsch', en: 'English', ru: 'Русский', zh: '中文' };
const INTL_LOCALES = { de: 'de-DE', en: 'en-US', ru: 'ru-RU', zh: 'zh-CN' };
const LANGUAGE_LABELS = { de: 'Sprache', en: 'Language', ru: 'Язык', zh: '语言' };
const COOKIE_NAME = 'vgt.lang';
const ATTRS = ['title', 'placeholder', 'aria-label', 'aria-description', 'alt'];
const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'CODE', 'PRE', 'TEXTAREA']);

let current = 'de';
let initialized = false;
let applying = false;
const textNodes = new Set();
const sources = new WeakMap();
const attrRecords = [];
const attrIndex = new WeakMap();
let patternCache = new Map();
let lowerCache = new Map();
let observer = null;

function normalizeLanguage(value) {
  if (typeof value !== 'string') return '';
  const code = value.trim().toLowerCase().split(/[-_]/)[0];
  return LANGUAGES.includes(code) ? code : '';
}

function detectLanguage() {
  const cookie = readCookie();
  const fromCookie = normalizeLanguage(cookie);
  if (fromCookie) return fromCookie;
  const candidates = [];
  if (Array.isArray(navigator.languages)) candidates.push(...navigator.languages);
  if (navigator.language) candidates.push(navigator.language);
  if (navigator.userLanguage) candidates.push(navigator.userLanguage);
  for (const candidate of candidates) {
    const code = normalizeLanguage(candidate);
    if (code) return code;
  }
  return 'en';
}

function readCookie() {
  try {
    for (const part of String(document.cookie || '').split(';')) {
      const [name, ...rest] = part.trim().split('=');
      if (name === COOKIE_NAME) return decodeURIComponent(rest.join('='));
    }
  } catch (error) {
    return '';
  }
  return '';
}

function writeCookie(language) {
  try {
    document.cookie = COOKIE_NAME + '=' + encodeURIComponent(language) + '; Path=/; Max-Age=31536000; SameSite=Lax';
  } catch (error) {
    /* cookie may be unavailable (hardened browser); the in-memory choice still applies */
  }
}

export function locale() {
  return INTL_LOCALES[current] || INTL_LOCALES.en;
}

export function language() {
  return current;
}

function dictionary() {
  return TRANSLATIONS[current] || null;
}

function lowerDictionary(languageCode) {
  if (lowerCache.has(languageCode)) return lowerCache.get(languageCode);
  const dict = TRANSLATIONS[languageCode];
  const lower = new Map();
  if (dict) {
    for (const [source, target] of Object.entries(dict)) {
      const key = source.toLowerCase();
      if (!lower.has(key)) lower.set(key, target);
    }
  }
  lowerCache.set(languageCode, lower);
  return lower;
}

function lookupExact(value) {
  const dict = dictionary();
  if (!dict) return value;
  if (Object.prototype.hasOwnProperty.call(dict, value)) return dict[value];
  // The source tree contains the same label in different letter cases
  // (e.g. "PRÜFUNG" in a badge and "Prüfung" in a table header). The fallback
  // keeps a single dictionary entry usable for both.
  const lowered = lowerDictionary(current).get(value.toLowerCase());
  return lowered !== undefined ? lowered : value;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function buildPatterns(languageCode) {
  const dict = TRANSLATIONS[languageCode];
  const patterns = [];
  if (!dict) return patterns;
  for (const [source, target] of Object.entries(dict)) {
    if (typeof target !== 'string' || !target) continue;
    if (!/\{\d+\}/.test(source)) continue;
    const placeholderNumbers = [];
    let regex = '^';
    let lastIndex = 0;
    const token = /\{(\d+)\}/g;
    let match;
    while ((match = token.exec(source)) !== null) {
      regex += escapeRegExp(source.slice(lastIndex, match.index));
      regex += '(.*?)';
      placeholderNumbers.push(Number(match[1]));
      lastIndex = match.index + match[0].length;
    }
    regex += escapeRegExp(source.slice(lastIndex)) + '$';
    try {
      patterns.push({ regex: new RegExp(regex, 'i'), target, placeholderNumbers, source });
    } catch (error) {
      /* an unusable pattern must not break localization */
    }
  }
  patterns.sort((a, b) => b.source.length - a.source.length);
  return patterns;
}

export function translateText(value) {
  if (typeof value !== 'string' || current === 'de') return value;
  const dict = dictionary();
  if (!dict) return value;
  const exact = lookupExact(value);
  if (exact !== value) return exact;
  if (!patternCache.has(current)) patternCache.set(current, buildPatterns(current));
  for (const pattern of patternCache.get(current)) {
    const match = pattern.regex.exec(value);
    if (!match) continue;
    const values = {};
    for (let index = 0; index < pattern.placeholderNumbers.length; index++) {
      // Captured values are often German labels (page names, enum labels);
      // translate them as well where the dictionary has an exact entry.
      values[pattern.placeholderNumbers[index]] = lookupExact(match[index + 1]);
    }
    return pattern.target.replace(/\{(\d+)\}/g, (token, number) => {
      const key = Number(number);
      return Object.prototype.hasOwnProperty.call(values, key) ? values[key] : token;
    });
  }
  return value;
}

function splitWhitespace(value) {
  const match = /^(\s*)([\s\S]*?)(\s*)$/.exec(value);
  return match ? { leading: match[1], core: match[2], trailing: match[3] } : { leading: '', core: value, trailing: '' };
}

function translateCore(node, core) {
  // The document title is composed as "GeDefense Titan · <page title>";
  // translate the segments independently so the product name stays intact.
  const parent = node.parentElement;
  if (parent && parent.tagName === 'TITLE') {
    return core.split(' · ').map((part) => translateText(part)).join(' · ');
  }
  return translateText(core);
}

function translateNode(node) {
  if (node.nodeType !== Node.TEXT_NODE) return;
  const parent = node.parentElement;
  if (!parent || SKIP_TAGS.has(parent.tagName)) return;
  if (parent.closest('[data-i18n-ignore]')) return;
  const parts = splitWhitespace(node.data);
  if (!parts.core) return;
  let source = sources.get(node);
  if (source === undefined) {
    source = parts;
    sources.set(node, source);
    textNodes.add(node);
  } else if (parts.core !== translateCore(node, source.core)) {
    source = parts;
    sources.set(node, source);
  }
  const translated = translateCore(node, source.core);
  const next = parts.leading + translated + parts.trailing;
  if (next !== node.data) {
    applying = true;
    node.data = next;
    applying = false;
  }
}

function translateAttribute(element, name) {
  if (!element.hasAttribute(name)) return;
  if (SKIP_TAGS.has(element.tagName)) return;
  let record = attrIndex.get(element);
  if (!record) {
    record = new Map();
    attrIndex.set(element, record);
  }
  const previous = record.get(name);
  const value = element.getAttribute(name);
  if (previous === undefined) {
    record.set(name, value);
    attrRecords.push({ element, name, source: value });
  } else if (value !== translateText(previous)) {
    record.set(name, value);
    for (const entry of attrRecords) {
      if (entry.element === element && entry.name === name) entry.source = value;
    }
  }
  const source = record.get(name);
  const translated = translateText(source);
  if (element.getAttribute(name) !== translated) {
    applying = true;
    element.setAttribute(name, translated);
    applying = false;
  }
}

function sweep(root) {
  if (!root || !root.ownerDocument) return;
  if (root.nodeType === Node.TEXT_NODE) {
    translateNode(root);
    return;
  }
  if (root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.DOCUMENT_FRAGMENT_NODE) return;
  const element = root.nodeType === Node.ELEMENT_NODE ? root : null;
  if (element && SKIP_TAGS.has(element.tagName)) return;
  if (element) for (const name of ATTRS) translateAttribute(element, name);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT, {
    acceptNode(node) {
      if (node.nodeType === Node.ELEMENT_NODE && SKIP_TAGS.has(node.tagName)) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });
  let node = walker.currentNode;
  while (node) {
    if (node.nodeType === Node.TEXT_NODE) translateNode(node);
    else if (node.nodeType === Node.ELEMENT_NODE) {
      for (const name of ATTRS) translateAttribute(node, name);
    }
    node = walker.nextNode();
  }
}

function applyAll() {
  for (const node of textNodes) {
    if (node.isConnected) {
      const source = sources.get(node);
      if (!source) continue;
      const next = source.leading + translateCore(node, source.core) + source.trailing;
      if (next !== node.data) {
        applying = true;
        node.data = next;
        applying = false;
      }
    }
  }
  for (const record of attrRecords) {
    if (record.element.isConnected) {
      const translated = translateText(record.source);
      if (record.element.getAttribute(record.name) !== translated) {
        applying = true;
        record.element.setAttribute(record.name, translated);
        applying = false;
      }
    }
  }
  const switcher = document.getElementById('languageSwitcher');
  if (switcher) {
    switcher.value = current;
    switcher.setAttribute('aria-label', LANGUAGE_LABELS[current] || LANGUAGE_LABELS.en);
    switcher.title = LANGUAGE_LABELS[current] || LANGUAGE_LABELS.en;
  }
}

function observe() {
  if (observer || typeof MutationObserver === 'undefined' || !document.body) return;
  observer = new MutationObserver((mutations) => {
    if (applying) return;
    for (const mutation of mutations) {
      if (mutation.type === 'childList') {
        for (const node of mutation.addedNodes) sweep(node);
      } else if (mutation.type === 'characterData') {
        translateNode(mutation.target);
      } else if (mutation.type === 'attributes' && mutation.attributeName) {
        translateAttribute(mutation.target, mutation.attributeName);
      }
    }
  });
  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: ATTRS,
  });
}

function bindSwitcher() {
  const switcher = document.getElementById('languageSwitcher');
  if (!switcher) return;
  switcher.value = current;
  switcher.addEventListener('change', () => setLanguage(switcher.value));
}

export function setLanguage(languageCode) {
  const code = normalizeLanguage(languageCode);
  if (!code) return;
  current = code;
  writeCookie(code);
  document.documentElement.lang = code;
  applyAll();
  globalThis.dispatchEvent(new CustomEvent('geodefense:languagechange', { detail: { language: code } }));
}

export function initI18n() {
  if (initialized) return;
  initialized = true;
  current = detectLanguage();
  document.documentElement.lang = current;
  bindSwitcher();
  sweep(document.head);
  sweep(document.body);
  applyAll();
  observe();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initI18n, { once: true });
} else {
  initI18n();
}
