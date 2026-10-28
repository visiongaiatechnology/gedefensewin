// STATUS: DIAMANT VGT SUPREME
'use strict';
/** Unit tests for the pure parts of web/list-stability.js (node --test).
 *
 *  The DOM integration is covered separately by the headless-Chromium
 *  regression test; these tests pin the arithmetic of the scroll anchor and the
 *  no-op render decision, including the edge cases that caused the Titan view to
 *  jump back to the top during live refresh.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  contentRelativeTop, isNearTop, restoreTarget, selectAnchor, shouldReplace, TOP_THRESHOLD,
} from '../src/GeDefense/windows/internal/server/web/list-stability.js';

test('isNearTop treats the top band and invalid values as top', () => {
  assert.equal(isNearTop(0), true);
  assert.equal(isNearTop(TOP_THRESHOLD), true);
  assert.equal(isNearTop(TOP_THRESHOLD + 1), false);
  assert.equal(isNearTop(600), false);
  assert.equal(isNearTop(Number.NaN), true);
  assert.equal(isNearTop(-4), true);
  assert.equal(isNearTop(4, 4), true);
});

test('selectAnchor picks the first partially visible row', () => {
  const rows = [
    { id: 'e1', top: -40, height: 60 },
    { id: 'e2', top: 20, height: 60 },
    { id: 'e3', top: 80, height: 60 },
  ];
  assert.deepEqual(selectAnchor(rows, 0), { id: 'e1', offset: -40 });
  assert.deepEqual(selectAnchor(rows, 30), { id: 'e2', offset: -10 });
  assert.deepEqual(selectAnchor(rows, 85), { id: 'e3', offset: -5 });
  assert.equal(selectAnchor([], 0), null);
  assert.equal(selectAnchor(null, 0), null);
  assert.equal(selectAnchor([{ id: 'x', top: 0, height: 0 }], 100), null);
});

test('restoreTarget keeps the anchor row at its viewport offset after prepend', () => {
  const snapshot = {
    scrollTop: 600, atTop: false, anchor: { id: 'e20', offset: -12 },
  };
  // One new event was prepended: every existing row moved down by 96 px.
  const shifted = [
    { id: 'e0', top: -696, height: 96 },
    { id: 'e20', top: 588, height: 96 },
  ];
  assert.equal(restoreTarget(snapshot, shifted), 600);
});

test('restoreTarget stays at the top for live-feed readers', () => {
  assert.equal(restoreTarget({ scrollTop: 0, atTop: true, anchor: { id: 'e1', offset: 0 } }, []), 0);
  assert.equal(restoreTarget({ scrollTop: 4, atTop: true, anchor: null }, []), 0);
});

test('restoreTarget falls back to the clamped old offset without an anchor', () => {
  assert.equal(restoreTarget({ scrollTop: 420, atTop: false, anchor: null }, []), 420);
  assert.equal(restoreTarget({ scrollTop: 420, atTop: false, anchor: { id: 'gone', offset: 0 } }, [{ id: 'other', top: 0, height: 10 }]), 420);
  assert.equal(restoreTarget({ scrollTop: -50, atTop: false, anchor: null }, []), 0);
  assert.equal(restoreTarget(null, []), 0);
  assert.equal(restoreTarget({ scrollTop: 500, atTop: false, anchor: { id: 'e2', offset: -10 } }, [{ id: 'e2', top: 4, height: 10 }]), 14);
});

test('shouldReplace is the no-op render decision', () => {
  assert.equal(shouldReplace('evt:1', 'evt:1'), false);
  assert.equal(shouldReplace('evt:1', 'evt:2'), true);
  assert.equal(shouldReplace(undefined, 'evt:1'), true);
});

test('contentRelativeTop converts viewport positions into list content positions', () => {
  assert.equal(contentRelativeTop(-21.8, 600), 578.2);
  assert.equal(contentRelativeTop(0, 0), 0);
  assert.equal(contentRelativeTop(120, 3116), 3236);
  assert.equal(contentRelativeTop(Number.NaN, 42), 42);
});

test('deep-scroll anchor resolves and restores after a prepended event', () => {
  const rowHeight = 82.6;
  const scrollTop = 3116;
  const rows = Array.from({ length: 44 }, (_, index) => ({
    id: `event:${index}`, top: index * rowHeight, height: rowHeight,
  }));
  const anchor = selectAnchor(rows, scrollTop);
  assert.ok(anchor, 'deep scroll offset must still produce an anchor row');
  assert.equal(anchor.id, 'event:37');
  const snapshot = { scrollTop, atTop: false, anchor };
  const shifted = [
    { id: 'event:new', top: 0, height: rowHeight },
    ...rows.map(row => ({ id: row.id, top: row.top + rowHeight, height: rowHeight })),
  ];
  const target = restoreTarget(snapshot, shifted);
  assert.equal(target, scrollTop + rowHeight);
  // The previously first visible row keeps its viewport offset after the prepend.
  const oldViewportTop = rows[37].top - scrollTop;
  const newViewportTop = shifted.find(row => row.id === 'event:37').top - target;
  assert.ok(Math.abs(oldViewportTop - newViewportTop) < 0.001);
});
