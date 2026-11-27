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
 * Round 3: smtpPass no longer lives in settings.json — it is a vault
 * secret ('smtp'). main.js resolves it (resolveEmailSettings) and
 * passes the resolved settings into sendMail/notify; this module
 * never touches the vault itself. A caller that passes no resolved
 * settings still reads the file, so a legacy plaintext smtpPass
 * keeps working until migration moves it.
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
  // smtpHost matters: without it a cleared host silently fell back to
  // smtp.gmail.com while the user believed mail was off/unconfigured.
  return Boolean(email && email.enabled && email.to && email.smtpUser && email.smtpPass && email.smtpHost);
}

// Which kinds this install wants mail for. Defaults: all on.
function wants(email, kind) {
  if (!email || !email.enabled) return false;
  if (kind === 'started') return email.notifyOnStart !== false;
  if (kind === 'finished' || kind === 'failed') return email.notifyOnFinish !== false;
  if (kind === 'missed') return email.notifyOnMissed !== false;
  return true;
}

async function sendMail(userDataDir, subject, text, emailSettings) {
  // Read the settings once: notify() used to read them, then sendMail
  // read them again, so a Settings change between the two reads could
  // send with a different host/password than the one that was checked.
  const email = emailSettings || readEmailSettings(userDataDir);
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
    const port = Number(email.smtpPort) || 465;
    // Port decides the encryption: 465 = implicit SSL, 587 = STARTTLS.
    // Company mail servers usually run on one of these two.
    // requireTLS on 587: STARTTLS used to be opportunistic, so on a
    // network that strips it the credentials and the mail went in
    // cleartext. Now the send fails loudly instead.
    // Timeouts: a hung SMTP server used to stall the main process
    // indefinitely (no timeout was set at all).
    const transporter = nodemailer.createTransport({
      host: email.smtpHost || 'smtp.gmail.com',
      port: port,
      secure: port === 465,
      requireTLS: port === 587,
      connectionTimeout: 30000,
      greetingTimeout: 30000,
      socketTimeout: 30000,
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
      (ok ? '' : ('\nError: ' + ((job && job.error) || 'check the app log for details.')));
  }
  if (kind === 'missed') {
    const list = (extra || []).map(function (m) {
      return '- ' + m.job.name + ' (was due ' + m.due.toLocaleString() + ')';
    }).join('\n');
    return 'TechVision Backup was not running, so these scheduled backups missed their time. ' +
      'They will be retried now that the app is open again — a job whose drive is missing, or whose vault is locked, waits instead of running.\n\n' + list + '\n\nTime checked: ' + when +
      '\nTip: keep Start with Windows on so schedules are not missed.';
  }
  return String(extra || '');
}

async function notify(userDataDir, kind, job, extra, emailSettings) {
  try {
    // emailSettings (vault-resolved, from main) wins when given; the
    // file read is the legacy fallback for a plaintext smtpPass that
    // migration has not moved yet.
    const email = emailSettings || readEmailSettings(userDataDir);
    if (!wants(email, kind)) return { sent: false, reason: 'off' };
    const subjects = {
      started: 'Backup started: ' + ((job && job.name) || ''),
      finished: 'Backup finished: ' + ((job && job.name) || ''),
      failed: 'Backup FAILED: ' + ((job && job.name) || ''),
      missed: 'Service was down — scheduled backup(s) missed'
    };
    return await sendMail(userDataDir, subjects[kind] || kind, eventText(kind, job, extra), email);
  } catch (e) {
    return { sent: false, reason: e && e.message ? e.message : String(e) };
  }
}

module.exports = { readEmailSettings, isConfigured, wants, sendMail, notify };
