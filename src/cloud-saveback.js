'use strict';
/**
 * TechVision Cloud — temp + save-back (main process).
 *
 * After a server file is opened from a temp copy, watch that copy
 * while the app is open. When it changes and stays stable (~2s
 * debounce), upload it back to the same server path — silently.
 * If the server copy changed since the download, do NOT overwrite:
 * report a conflict instead and stop watching that file.
 *
 * Pure Node (fs only) — no Electron imports — so the harness can
 * require it directly. The caller injects:
 *   listEntry(serverId, relPath) -> Promise<{ size, mtime } | null>
 *     the server copy right now (null when it is gone);
 *   uploadFile(serverId, relPath, localPath) -> Promise<void>
 *     upload the temp copy back over the same server path;
 *   notify(event) — { kind: 'saved-back' | 'conflict' | 'error',
 *     serverId, relPath, name, error? }.
 *
 * Watching is session-only: watches live in this process only, so a
 * restart never re-uploads a stale temp file. Polling (fs.statSync)
 * instead of fs.watch: editors that save by rename replace the
 * file, and a stat poll sees the new file where a watch on the old
 * inode would go silent.
 */
const fs = require('fs');

const DEFAULT_POLL_MS = 1000;
const DEFAULT_DEBOUNCE_MS = 2000;

function createSaveback(deps, opts) {
  const pollMs = (opts && opts.pollMs) || DEFAULT_POLL_MS;
  const debounceMs = (opts && opts.debounceMs) || DEFAULT_DEBOUNCE_MS;
  const watches = new Map(); // key -> watch

  function key(serverId, relPath) { return String(serverId) + '\0' + String(relPath); }
  function nameOf(relPath) { return String(relPath || '').split('/').pop(); }

  function stopWatch(w) {
    if (!w) return;
    w.stopped = true;
    if (w.poller) { clearInterval(w.poller); w.poller = null; }
    if (w.timer) { clearTimeout(w.timer); w.timer = null; }
    watches.delete(key(w.serverId, w.relPath));
  }

  function scheduleUpload(w) {
    if (w.timer) clearTimeout(w.timer);
    w.timer = setTimeout(() => { w.timer = null; tryUpload(w); }, debounceMs);
  }

  async function tryUpload(w) {
    if (w.stopped || w.busy) return;
    let st;
    try { st = fs.statSync(w.localPath); } catch (e) { stopWatch(w); return; } // deleted
    if (st.size !== w.lastStat.size || st.mtimeMs !== w.lastStat.mtimeMs) {
      // Changed again during the debounce — re-arm on the new state.
      w.lastStat = { size: st.size, mtimeMs: st.mtimeMs };
      scheduleUpload(w);
      return;
    }
    w.busy = true;
    try {
      const now = await deps.listEntry(w.serverId, w.relPath);
      if (!now) {
        deps.notify({ kind: 'error', serverId: w.serverId, relPath: w.relPath, name: nameOf(w.relPath), error: 'The file is no longer on the server.' });
        stopWatch(w);
        return;
      }
      if (now.size !== w.snapshot.size || now.mtime !== w.snapshot.mtime) {
        // Someone changed the server copy since the download: never
        // silently overwrite their version.
        deps.notify({ kind: 'conflict', serverId: w.serverId, relPath: w.relPath, name: nameOf(w.relPath) });
        stopWatch(w);
        return;
      }
      await deps.uploadFile(w.serverId, w.relPath, w.localPath);
      // The server copy just changed (by us) — refresh the snapshot
      // so the next edit does not false-conflict against the old one.
      const after = await deps.listEntry(w.serverId, w.relPath);
      if (after) w.snapshot = { size: after.size, mtime: after.mtime };
      deps.notify({ kind: 'saved-back', serverId: w.serverId, relPath: w.relPath, name: nameOf(w.relPath) });
    } catch (e) {
      deps.notify({ kind: 'error', serverId: w.serverId, relPath: w.relPath, name: nameOf(w.relPath), error: e && e.message ? e.message : String(e) });
      // Keep watching: a hiccup must not kill the watch — the next
      // edit retries the upload.
    } finally { w.busy = false; }
  }

  // Start (or replace) the watch for one temp copy. snapshot is the
  // server copy's { size, mtime } taken at download time.
  function watch(serverId, relPath, localPath, snapshot) {
    if (!serverId || !relPath || !localPath || !snapshot) return null;
    const k = key(serverId, relPath);
    const old = watches.get(k);
    if (old) stopWatch(old);
    let st;
    try { st = fs.statSync(localPath); } catch (e) { return null; }
    const w = {
      serverId, relPath, localPath,
      snapshot: { size: snapshot.size, mtime: snapshot.mtime },
      lastStat: { size: st.size, mtimeMs: st.mtimeMs },
      poller: null, timer: null, stopped: false, busy: false,
    };
    w.poller = setInterval(() => {
      if (w.stopped) return;
      let cur;
      try { cur = fs.statSync(localPath); } catch (e) { stopWatch(w); return; } // deleted
      if (cur.size !== w.lastStat.size || cur.mtimeMs !== w.lastStat.mtimeMs) {
        w.lastStat = { size: cur.size, mtimeMs: cur.mtimeMs };
        scheduleUpload(w);
      }
    }, pollMs);
    if (w.poller.unref) w.poller.unref();
    watches.set(k, w);
    return w;
  }

  function stop(serverId, relPath) {
    if (relPath) { stopWatch(watches.get(key(serverId, relPath))); return; }
    for (const w of [...watches.values()]) if (w.serverId === serverId) stopWatch(w);
  }

  function stopAll() { for (const w of [...watches.values()]) stopWatch(w); }
  function count() { return watches.size; }

  return { watch, stop, stopAll, count };
}

module.exports = { createSaveback };
