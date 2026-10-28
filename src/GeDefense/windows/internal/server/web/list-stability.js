// STATUS: DIAMANT VGT SUPREME
'use strict';
/** Scroll-stable list rendering for the Titan control center.
 *
 *  The control plane is polled every few seconds. Replacing a list wholesale
 *  while the operator is reading it is a usability defect: the page height
 *  briefly collapses, the scroll position is clamped back towards the top and
 *  open evidence details or keyboard focus are lost. The helpers in this module
 *  keep the operator's reading position stable:
 *
 *   - refresh BEFORE render (callers fetch first, then call renderStable),
 *   - skip the DOM update entirely while the content signature is unchanged,
 *   - otherwise remember the first visible row (anchor) plus its viewport
 *     offset, the open <details> nodes and the focused row, rebuild the list and
 *     restore exactly that state,
 *   - stay at the top when the operator is at the top (live feed behaviour).
 *
 *  Everything is framework-free, uses DOM construction only (no innerHTML) and
 *  is bounded to the affected list node.
 */

/** Scroll distance (px) up to which the list is treated as "at the top". */
export const TOP_THRESHOLD = 8;

/** isNearTop reports whether scrollTop counts as the live-feed top position. */
export function isNearTop(scrollTop, threshold = TOP_THRESHOLD) {
  const value = Number(scrollTop);
  if (!Number.isFinite(value)) return true;
  return value <= Math.max(0, Number(threshold) || 0);
}

/** shouldReplace turns two content signatures into the render decision. */
export function shouldReplace(previousSignature, nextSignature) {
  return previousSignature !== nextSignature;
}

/**
 * selectAnchor picks the first row that is (at least partially) visible at the
 * current scroll offset. rows: [{id, top, height}] with top relative to the
 * scroll container's viewport. Returns {id, offset} or null.
 */
export function selectAnchor(rows, scrollTop) {
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const position = Number.isFinite(Number(scrollTop)) ? Number(scrollTop) : 0;
  for (const row of rows) {
    if (!row || row.id === undefined || row.id === null) continue;
    const top = Number(row.top) || 0;
    const height = Math.max(0, Number(row.height) || 0);
    if (top + height > position + 1) {
      return { id: String(row.id), offset: top - position };
    }
  }
  return null;
}

/**
 * restoreTarget computes the scroll offset that keeps the captured anchor row
 * at its previous viewport offset. When the operator was at the top, the top is
 * kept so new events stay visible; when the anchor row disappeared (page
 * content changed by more than one page) the previous offset is kept clamped.
 */
export function restoreTarget(snapshot, rows) {
  if (!snapshot) return 0;
  if (snapshot.atTop) return 0;
  const previous = Math.max(0, Number(snapshot.scrollTop) || 0);
  if (snapshot.anchor && Array.isArray(rows)) {
    const match = rows.find(row => row && String(row.id) === String(snapshot.anchor.id));
    if (match) {
      return Math.max(0, (Number(match.top) || 0) - (Number(snapshot.anchor.offset) || 0));
    }
  }
  return previous;
}

function scrollContainerFor(element) {
  let current = element?.parentElement;
  while (current && current !== document.body && current !== document.documentElement) {
    const style = globalThis.getComputedStyle(current);
    if (style && (style.overflowY === 'auto' || style.overflowY === 'scroll')) {
      return { element: current, window: false };
    }
    current = current.parentElement;
  }
  const scroller = document.scrollingElement || document.documentElement;
  return { element: scroller, window: true };
}

/**
 * contentRelativeTop converts a viewport-relative row top into the row's
 * content-relative position inside the scroll container. selectAnchor and
 * restoreTarget work with content positions; mixing viewport coordinates into
 * them breaks the anchor at deep scroll offsets (the first fully visible row is
 * then compared against the wrong origin and the fallback jumps by one row).
 */
export function contentRelativeTop(viewportTop, scrollTop) {
  return (Number(viewportTop) || 0) + (Number(scrollTop) || 0);
}

function measureRows(host, scrollerTop, scrollTop) {
  const rows = [];
  for (const row of host.children) {
    const id = row?.dataset?.titanRow;
    if (!id) continue;
    const rect = row.getBoundingClientRect();
    rows.push({ id, top: contentRelativeTop(rect.top - scrollerTop, scrollTop), height: rect.height });
  }
  return rows;
}

/** captureListRenderState records scroll position, anchor row, open details and focus. */
export function captureListRenderState(host) {
  if (!host || typeof host.getBoundingClientRect !== 'function') return null;
  const scroller = scrollContainerFor(host);
  if (!scroller.element) return null;
  const scrollerRect = scroller.window ? { top: 0 } : scroller.element.getBoundingClientRect();
  const scrollTop = scroller.window
    ? Number(globalThis.scrollY) || 0
    : Number(scroller.element.scrollTop) || 0;
  const rows = measureRows(host, scrollerRect.top, scrollTop);
  const expanded = [];
  for (const details of host.querySelectorAll('details[open]')) {
    const row = details.closest('[data-titan-row]');
    if (row?.dataset?.titanRow) expanded.push(row.dataset.titanRow);
  }
  const focusRow = document.activeElement?.closest?.('[data-titan-row]');
  return {
    scroller,
    scrollerTop: scrollerRect.top,
    scrollTop,
    atTop: isNearTop(scrollTop),
    anchor: selectAnchor(rows, scrollTop),
    expanded,
    focusRow: focusRow?.dataset?.titanRow || '',
    focusTag: document.activeElement?.tagName || '',
    focusText: document.activeElement?.textContent || '',
  };
}

function applyScroll(scroller, target) {
  if (!scroller?.element) return;
  if (scroller.window) {
    globalThis.scrollTo(0, target);
    return;
  }
  scroller.element.scrollTop = target;
}

/** restoreListRenderState restores the captured position, details and focus. */
export function restoreListRenderState(host, snapshot) {
  if (!host || !snapshot?.scroller) return;
  const scrollerRect = snapshot.scroller.window ? { top: 0 } : snapshot.scroller.element.getBoundingClientRect();
  const currentScrollTop = snapshot.scroller.window
    ? Number(globalThis.scrollY) || 0
    : Number(snapshot.scroller.element.scrollTop) || 0;
  const rows = measureRows(host, scrollerRect.top, currentScrollTop);
  applyScroll(snapshot.scroller, restoreTarget(snapshot, rows));
  for (const id of snapshot.expanded || []) {
    const row = host.querySelector(`[data-titan-row="${CSS.escape(id)}"]`);
    const details = row?.querySelector('details');
    if (details) details.open = true;
  }
  if (snapshot.focusRow) {
    const row = host.querySelector(`[data-titan-row="${CSS.escape(snapshot.focusRow)}"]`);
    const candidate = row?.querySelector('button, summary, [tabindex]');
    if (candidate && typeof candidate.focus === 'function') {
      candidate.focus({ preventScroll: true });
    }
  }
}

const signatures = new WeakMap();

/**
 * renderStable renders host through build() only when signature changed. The
 * scroll anchor, open details and focus are captured before the replacement and
 * restored after it. Returns true when the DOM was updated.
 */
export function renderStable(host, signature, build) {
  if (!host || typeof build !== 'function') return false;
  const previous = signatures.get(host);
  if (!shouldReplace(previous, signature)) return false;
  const snapshot = captureListRenderState(host);
  signatures.set(host, signature);
  host.replaceChildren(build());
  restoreListRenderState(host, snapshot);
  return true;
}

/** resetListSignature drops the remembered signature (e.g. on explicit reload). */
export function resetListSignature(host) {
  if (host) signatures.delete(host);
}

/**
 * resetVisibleListPosition scrolls the list's scroll container so the list
 * starts at the container viewport (used for explicit filter/pagination changes,
 * never for background refresh).
 */
export function resetVisibleListPosition(host) {
  if (!host) return;
  const scroller = scrollContainerFor(host);
  if (!scroller.element) return;
  const scrollerTop = scroller.window ? 0 : scroller.element.getBoundingClientRect().top;
  const target = Math.max(0, host.getBoundingClientRect().top - scrollerTop + (scroller.window ? Number(globalThis.scrollY) || 0 : Number(scroller.element.scrollTop) || 0));
  applyScroll(scroller, target);
}
