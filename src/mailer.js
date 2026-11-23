/**
 * TechVision Backup — email notifications (main process only).
 * Sends mail through the user's own SMTP account (Gmail preset:
 * smtp.gmail.com:465). Lazy-loads nodemailer so a missing install
 * never crashes the app — sending just reports "not installed".
 *
 * Settings live in settings.json under `email`:
 *   { enabled, notifyOnStart, notifyOnFinish, notifyOnMissed,
 *     to, smtpHost, smtpPort, smtpSecure, smtpUser, smtpPass }
 * smtpPass is a Gmail *App Password* (Google Account -> Security ->
 * 2-Step Verification -> App passwords), never the account password.
 */
const fs = require('fs');
const path = require('path');

function readEmailSettings(userDataDir) {
  try {
    const p = path.join(userDataDir, '.techvision', 'settings.json');
    if (!fs.existsSync(p)) return {};
    const s = JSON.parse(fs.readFileSync(p, 'utf-8'));
    return (s && typeof s.email === 'object' && s.email) || {};
  } catch (e) {
    return {};
  }
}

function isConfigured(email) {
  return Boolean(email && email.enabled && email.to && email.smtpUser && email.smtpPass);
}

// Which kinds this install wants mail for. Defaults: all on.
function wants(email, kind) {
  if (!email || !email.enabled) return false;
  if (kind === 'started') return email.notifyOnStart !== false;
  if (kind === 'finished' || kind === 'failed') return email.notifyOnFinish !== false;
  if (kind === 'missed') return email.notifyOnMissed !== false;
  return true;
}

async function sendMail(userDataDir, subject, text) {
  const email = readEmailSettings(userDataDir);
  if (!email.enabled) return { sent: false, reason: 'Email notifications are off in Settings.' };
  if (!email.to || !email.smtpUser || !email.smtpPass) {
    return { sent: false, reason: 'Email notifications are not set up: fill in the recipient, Gmail address and App Password in Settings.' };
  }
  let nodemailer;
  try {
    nodemailer = require('nodemailer');
  } catch (e) {
    return { sent: false, reason: 'nodemailer is not installed yet — run npm install in the project folder.' };
  }
  try {
    const transporter = nodemailer.createTransport({
      host: email.smtpHost || 'smtp.gmail.com',
      port: Number(email.smtpPort) || 465,
      secure: email.smtpSecure !== false,
      auth: { user: email.smtpUser, pass: email.smtpPass }
    });
    await transporter.sendMail({
      from: '"TechVision Backup" <' + email.smtpUser + '>',
      to: email.to,
      subject: '[TechVision Backup] ' + subject,
      text: text
    });
    return { sent: true };
  } catch (e) {
    return { sent: false, reason: e && e.message ? e.message : String(e) };
  }
}

function formatBytes(n) {
  if (!n && n !== 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0; let v = Number(n) || 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(v >= 100 ? 0 : 1) + ' ' + units[i];
}

function eventText(kind, job, extra) {
  const name = (job && job.name) || 'backup job';
  const when = new Date().toLocaleString();
  if (kind === 'started') {
    return 'Backup started: ' + name + ' (' + ((job && job.type) || 'full') + ')\nTime: ' + when +
      '\nSource: ' + ((job && job.source) || '-') + '\nDestination: ' + ((job && job.destination) || '-');
  }
  if (kind === 'finished' || kind === 'failed') {
    const ok = kind === 'finished';
    return 'Backup ' + (ok ? 'finished' : 'FAILED') + ': ' + name + ' (' + ((job && job.type) || 'full') + ')' +
      '\nTime: ' + when + '\nFiles: ' + ((job && job.files) || 0) +
      '\nSize: ' + formatBytes(job && job.size) + '\nDuration: ' + ((job && job.duration) || 0) + 's' +
      (ok ? '' : '\nCheck the app log for the error.');
  }
  if (kind === 'missed') {
    const list = (extra || []).map(function (m) {
      return '- ' + m.job.name + ' (was due ' + m.due.toLocaleString() + ')';
    }).join('\n');
    return 'TechVision Backup was not running, so these scheduled backups missed their time. ' +
      'They will run now that the app is open again.\n\n' + list + '\n\nTime checked: ' + when +
      '\nTip: keep Start with Windows on so schedules are not missed.';
  }
  return String(extra || '');
}

async function notify(userDataDir, kind, job, extra) {
  try {
    const email = readEmailSettings(userDataDir);
    if (!wants(email, kind)) return { sent: false, reason: 'off' };
    const subjects = {
      started: 'Backup started: ' + ((job && job.name) || ''),
      finished: 'Backup finished: ' + ((job && job.name) || ''),
      failed: 'Backup FAILED: ' + ((job && job.name) || ''),
      missed: 'Service was down — scheduled backup(s) missed'
    };
    return await sendMail(userDataDir, subjects[kind] || kind, eventText(kind, job, extra));
  } catch (e) {
    return { sent: false, reason: e && e.message ? e.message : String(e) };
  }
}

module.exports = { readEmailSettings, isConfigured, wants, sendMail, notify };
