// Nova Dashboard — Service Worker v2
// 30-min reminders, 9am recap, background calendar sync

const CACHE_NAME = 'nova-v2';
const DASHBOARD_URL = 'https://ligourio.github.io/Nova-Dashboard';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

// ── PUSH NOTIFICATIONS ──
self.addEventListener('push', e => {
  const data = e.data?.json() || {};
  const title = data.title || 'Nova';
  const body  = data.body  || 'You have a reminder.';
  e.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon: '/Nova-Dashboard/icon-192.png',
      badge: '/Nova-Dashboard/icon-192.png',
      tag: data.tag || 'nova-reminder',
      renotify: true,
      data: { url: DASHBOARD_URL },
      actions: [
        { action: 'open',    title: 'Open Nova' },
        { action: 'dismiss', title: 'Dismiss'   },
      ],
    })
  );
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  if (e.action === 'dismiss') return;
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      const match = list.find(c => c.url === DASHBOARD_URL);
      if (match) return match.focus();
      return clients.openWindow(DASHBOARD_URL);
    })
  );
});

// ── MESSAGE HANDLER ──
self.addEventListener('message', e => {
  if (e.data?.type === 'SCHEDULE_ALL') {
    const { events, recap } = e.data;
    scheduleEventReminders(events || []);
    scheduleDailyRecap(recap || []);
  }
  if (e.data?.type === 'SHOW_RECAP') {
    showRecapNotification(e.data.events || [], e.data.summary || '');
  }
});

// ── EVENT REMINDERS (10 min + 30 min before) ──
const scheduledReminders = new Set();

function scheduleEventReminders(events) {
  events.forEach(ev => {
    if (!ev.start) return;
    const start = new Date(ev.start).getTime();
    const now = Date.now();

    [30, 10].forEach(mins => {
      const fireAt = start - mins * 60 * 1000;
      const delay = fireAt - now;
      const key = `${ev.title}-${mins}`;
      if (delay < 0 || delay > 12 * 3600 * 1000 || scheduledReminders.has(key)) return;
      scheduledReminders.add(key);
      setTimeout(() => {
        self.registration.showNotification(`📅 ${ev.title}`, {
          body: `Starting in ${mins} minutes`,
          icon: '/Nova-Dashboard/icon-192.png',
          tag: `event-${ev.title}-${mins}`,
          data: { url: DASHBOARD_URL },
        });
      }, delay);
    });
  });
}

// ── 9AM DAILY RECAP ──
let recapScheduled = false;

function scheduleDailyRecap(events) {
  if (recapScheduled) return;
  recapScheduled = true;

  const now  = new Date();
  const next = new Date();
  next.setHours(9, 0, 0, 0);
  if (next <= now) next.setDate(next.getDate() + 1);
  const delay = next - now;

  setTimeout(() => {
    recapScheduled = false;
    showRecapNotification(events, '');
    scheduleDailyRecap(events); // reschedule for tomorrow
  }, delay);
}

function showRecapNotification(events, summary) {
  const today = new Date().toDateString();
  const todayEvents = events.filter(ev => {
    try { return new Date(ev.start).toDateString() === today; } catch { return false; }
  });

  const body = todayEvents.length > 0
    ? todayEvents.slice(0, 4).map(ev => {
        const t = new Date(ev.start).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
        return `• ${t} ${ev.title}`;
      }).join('\n')
    : summary || 'No events today — free day!';

  self.registration.showNotification('☀️ Good morning, Demetri!', {
    body: `Here's your day:\n${body}`,
    icon: '/Nova-Dashboard/icon-192.png',
    badge: '/Nova-Dashboard/icon-192.png',
    tag: 'daily-recap',
    requireInteraction: false,
    data: { url: DASHBOARD_URL },
  });
}

// ── BACKGROUND SYNC (periodic calendar refresh signal) ──
self.addEventListener('periodicsync', e => {
  if (e.tag === 'calendar-sync') {
    e.waitUntil(
      self.clients.matchAll({ type: 'window' }).then(list => {
        list.forEach(client => client.postMessage({ type: 'BG_SYNC_CALENDAR' }));
      })
    );
  }
});
