'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('gate', {
  onInitial: (fn) => ipcRenderer.on('log:initial', (_e, rows) => fn(rows)),
  onAppend: (fn) => ipcRenderer.on('log:append', (_e, rows) => fn(rows)),
  onEvent: (fn) => ipcRenderer.on('event:push', (_e, ev) => fn(ev)),
  onGateRequest: (fn) => ipcRenderer.on('gate:request', (_e, req) => fn(req)),
  onGateResolve: (fn) => ipcRenderer.on('gate:resolve', (_e, r) => fn(r)),
  onStatus: (fn) => ipcRenderer.on('gate:status', (_e, s) => fn(s)),

  respond: (id, decision) => ipcRenderer.invoke('gate:respond', { id, decision }),
  copy: (text) => ipcRenderer.invoke('clip:copy', text),
  logDir: () => ipcRenderer.invoke('log:dir'),
  openLogs: () => ipcRenderer.invoke('log:open'),
  close: () => ipcRenderer.invoke('win:close'),
  minimize: () => ipcRenderer.invoke('win:minimize'),
  pin: (on) => ipcRenderer.invoke('win:pin', on),
});
