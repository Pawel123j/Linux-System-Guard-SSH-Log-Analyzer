'use client';

import {
  ChangeEvent,
  DragEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

type EventType =
  | 'accepted'
  | 'failed'
  | 'invalid_user'
  | 'connection_closed'
  | 'unknown';

type RiskLevel = 'Wysokie' | 'Średnie' | 'Niskie';
type EventFilter = 'all' | EventType;
type RiskFilter = 'all' | 'high' | 'medium';

type AuthEvent = {
  id: string;
  timestamp: string;
  hostname: string;
  pid?: string;
  eventType: EventType;
  authMethod?: string;
  username?: string;
  sourceIp?: string;
  sourcePort?: string;
  preauth?: boolean;
  invalidUser?: boolean;
  rawLine: string;
};

type IpSummary = {
  ip: string;
  total: number;
  failed: number;
  accepted: number;
  invalidUsers: number;
  rootAttempts: number;
  users: string[];
  firstSeen: string;
  lastSeen: string;
  risk: RiskLevel;
  score: number;
};

type SecurityPolicy = {
  highFailureThreshold: number;
  mediumFailureThreshold: number;
  rootAttemptThreshold: number;
  trustedIps: string[];
  trustedUsers: string[];
};

type HistorySnapshot = {
  id: string;
  createdAt: string;
  sourceName: string;
  total: number;
  failed: number;
  accepted: number;
  suspicious: number;
  uniqueIps: number;
  blocked: number;
};

type BlockedIp = {
  ip: string;
  reason: string;
  addedAt: string;
  failed: number;
  risk: RiskLevel;
};

type AlertSettings = {
  browser: boolean;
  emailAddress: string;
  slackWebhook: string;
  slackAutomatic: boolean;
};

type MonitorSettings = {
  endpoint: string;
  intervalSeconds: number;
};

type MonitorStatus = 'zatrzymany' | 'łączenie' | 'aktywny' | 'błąd';

const DEFAULT_POLICY: SecurityPolicy = {
  highFailureThreshold: 10,
  mediumFailureThreshold: 5,
  rootAttemptThreshold: 3,
  trustedIps: [],
  trustedUsers: [],
};

const DEFAULT_ALERT_SETTINGS: AlertSettings = {
  browser: false,
  emailAddress: '',
  slackWebhook: '',
  slackAutomatic: false,
};

const DEFAULT_MONITOR_SETTINGS: MonitorSettings = {
  endpoint: 'http://127.0.0.1:8789/events',
  intervalSeconds: 10,
};

const STORAGE_KEYS = {
  history: 'system-guard-history-v1',
  blocklist: 'system-guard-blocklist-v1',
  policy: 'system-guard-policy-v1',
  alerts: 'system-guard-alerts-v1',
  monitor: 'system-guard-monitor-v1',
};

const SAMPLE_LOG = [
  'Aug 29 08:12:01 web-01 sshd[1824]: Failed password for root from 198.51.100.23 port 48510 ssh2',
  'Aug 29 08:12:07 web-01 sshd[1826]: Failed password for root from 198.51.100.23 port 48522 ssh2',
  'Aug 29 08:12:12 web-01 sshd[1828]: Failed password for admin from 198.51.100.23 port 48536 ssh2',
  'Aug 29 08:12:20 web-01 sshd[1831]: Failed password for root from 198.51.100.23 port 48540 ssh2',
  'Aug 29 08:12:29 web-01 sshd[1834]: Failed password for deploy from 198.51.100.23 port 48544 ssh2',
  'Aug 29 08:12:37 web-01 sshd[1837]: Failed password for root from 198.51.100.23 port 48561 ssh2',
  'Aug 29 08:12:46 web-01 sshd[1840]: Failed password for root from 198.51.100.23 port 48578 ssh2',
  'Aug 29 08:12:59 web-01 sshd[1843]: Failed password for root from 198.51.100.23 port 48582 ssh2',
  'Aug 29 08:13:08 web-01 sshd[1846]: Failed password for root from 198.51.100.23 port 48595 ssh2',
  'Aug 29 08:13:14 web-01 sshd[1849]: Failed password for root from 198.51.100.23 port 48604 ssh2',
  'Aug 29 08:13:21 web-01 sshd[1852]: Failed password for root from 198.51.100.23 port 48618 ssh2',
  'Aug 29 08:14:22 web-01 sshd[1861]: Accepted publickey for deploy from 2001:db8:8a2e:370:7334 port 54218 ssh2: ED25519 SHA256:XyZ',
  'Aug 29 08:15:03 web-01 sshd[1864]: Accepted password for admin from 203.0.113.10 port 51342 ssh2',
  'Aug 29 08:16:40 web-01 sshd[1870]: Connection closed by authenticating user root 203.0.113.72 port 55516 [preauth]',
  'Aug 29 08:17:05 web-01 sshd[1874]: Invalid user oracle from 198.51.100.78 port 57492',
  'Aug 29 08:17:06 web-01 sshd[1874]: Failed password for invalid user oracle from 198.51.100.78 port 57492 ssh2',
  'Aug 29 08:17:18 web-01 sshd[1878]: Invalid user postgres from 198.51.100.78 port 57508',
  'Aug 29 08:17:19 web-01 sshd[1878]: Failed password for invalid user postgres from 198.51.100.78 port 57508 ssh2',
  'Aug 29 08:18:42 web-01 sshd[1886]: Failed publickey for git from 203.0.113.45 port 56004 ssh2: RSA SHA256:AbCdEf',
  'Aug 29 08:19:04 web-01 sshd[1890]: Failed publickey for git from 203.0.113.45 port 56018 ssh2: RSA SHA256:AbCdEf',
  'Aug 29 08:19:21 web-01 sshd[1895]: Failed publickey for git from 203.0.113.45 port 56031 ssh2: RSA SHA256:AbCdEf',
  'Aug 29 08:20:10 web-01 sshd[1902]: Connection closed by invalid user oracle 198.51.100.78 port 57492 [preauth]',
  'Aug 29 08:21:44 web-01 sshd[1910]: Accepted publickey for deploy from 203.0.113.77 port 41210 ssh2: ED25519 SHA256:KlmNoP',
  'Aug 29 08:23:02 web-01 sshd[1917]: Connection closed by 198.51.100.50 port 46211 [preauth]',
].join('\n');

const EVENT_META: Record<EventType, { label: string; badge: string; dot: string }> = {
  accepted: {
    label: 'Zalogowano',
    badge: 'border-emerald-400/20 bg-emerald-400/10 text-emerald-200',
    dot: 'bg-emerald-300',
  },
  failed: {
    label: 'Odrzucono',
    badge: 'border-rose-400/20 bg-rose-400/10 text-rose-200',
    dot: 'bg-rose-300',
  },
  invalid_user: {
    label: 'Nieznany użytkownik',
    badge: 'border-amber-400/20 bg-amber-400/10 text-amber-100',
    dot: 'bg-amber-300',
  },
  connection_closed: {
    label: 'Przerwano połączenie',
    badge: 'border-sky-400/20 bg-sky-400/10 text-sky-100',
    dot: 'bg-sky-300',
  },
  unknown: {
    label: 'Nierozpoznany wpis',
    badge: 'border-slate-400/20 bg-slate-400/10 text-slate-200',
    dot: 'bg-slate-300',
  },
};

function parseAuthLog(content: string): AuthEvent[] {
  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((rawLine, index) => {
      const header = rawLine.match(
        /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd(?:\[(\d+)\])?:\s+(.*)$/,
      );

      if (!header) {
        return {
          id: index + '-' + rawLine,
          timestamp: '—',
          hostname: '—',
          eventType: 'unknown' as const,
          rawLine,
        };
      }

      const rawTimestamp = header[1];
      const hostname = header[2];
      const pid = header[3];
      const message = header[4];
      const base = {
        id: index + '-' + rawLine,
        timestamp: rawTimestamp.replace(/\s+/g, ' '),
        hostname,
        pid,
        rawLine,
      };

      const accepted = message.match(
        /^Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
      );
      if (accepted) {
        return {
          ...base,
          eventType: 'accepted' as const,
          authMethod: accepted[1],
          username: accepted[2],
          sourceIp: accepted[3],
          sourcePort: accepted[4],
        };
      }

      const failed = message.match(
        /^Failed\s+(\S+)\s+for\s+(invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
      );
      if (failed) {
        return {
          ...base,
          eventType: 'failed' as const,
          authMethod: failed[1],
          invalidUser: Boolean(failed[2]),
          username: failed[3],
          sourceIp: failed[4],
          sourcePort: failed[5],
        };
      }

      const invalidUser = message.match(
        /^Invalid user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
      );
      if (invalidUser) {
        return {
          ...base,
          eventType: 'invalid_user' as const,
          username: invalidUser[1],
          sourceIp: invalidUser[2],
          sourcePort: invalidUser[3],
          invalidUser: true,
        };
      }

      const closedInvalid = message.match(
        /^Connection closed by invalid user\s+(\S+)\s+(\S+)\s+port\s+(\d+)(.*)$/,
      );
      if (closedInvalid) {
        return {
          ...base,
          eventType: 'connection_closed' as const,
          username: closedInvalid[1],
          sourceIp: closedInvalid[2],
          sourcePort: closedInvalid[3],
          preauth: closedInvalid[4].includes('[preauth]'),
          invalidUser: true,
        };
      }

      const closedAuthenticating = message.match(
        /^Connection closed by authenticating user\s+(\S+)\s+(\S+)\s+port\s+(\d+)(.*)$/,
      );
      if (closedAuthenticating) {
        return {
          ...base,
          eventType: 'connection_closed' as const,
          username: closedAuthenticating[1],
          sourceIp: closedAuthenticating[2],
          sourcePort: closedAuthenticating[3],
          preauth: closedAuthenticating[4].includes('[preauth]'),
        };
      }

      const closed = message.match(
        /^Connection closed by\s+(\S+)\s+port\s+(\d+)(.*)$/,
      );
      if (closed) {
        return {
          ...base,
          eventType: 'connection_closed' as const,
          sourceIp: closed[1],
          sourcePort: closed[2],
          preauth: closed[3].includes('[preauth]'),
        };
      }

      return { ...base, eventType: 'unknown' as const };
    });
}

function calculateRisk(
  summary: Omit<IpSummary, 'risk' | 'score'>,
  policy: SecurityPolicy,
  trusted: boolean,
) {
  if (trusted) {
    return { score: 0, risk: 'Niskie' as const };
  }

  const broadTargeting =
    summary.failed >= policy.mediumFailureThreshold && summary.users.length >= 3;
  const score =
    (summary.failed >= policy.highFailureThreshold
      ? 5
      : summary.failed >= policy.mediumFailureThreshold
        ? 3
        : summary.failed >= Math.max(1, policy.mediumFailureThreshold - 2)
          ? 1
          : 0) +
    (summary.invalidUsers >= 4 ? 3 : summary.invalidUsers >= 2 ? 1 : 0) +
    (summary.rootAttempts >= policy.rootAttemptThreshold ? 2 : 0) +
    (broadTargeting ? 2 : 0);

  return {
    score,
    risk:
      score >= 5
        ? ('Wysokie' as const)
        : score >= 2
          ? ('Średnie' as const)
          : ('Niskie' as const),
  };
}

function makeIpSummaries(
  events: AuthEvent[],
  policy: SecurityPolicy = DEFAULT_POLICY,
): IpSummary[] {
  const trustedIps = new Set(
    policy.trustedIps.map((ip) => ip.trim().toLowerCase()).filter(Boolean),
  );
  const summaries = new Map<
    string,
    Omit<IpSummary, 'risk' | 'score'> & { userSet: Set<string> }
  >();

  events.forEach((event) => {
    if (!event.sourceIp) return;
    const current = summaries.get(event.sourceIp) ?? {
      ip: event.sourceIp,
      total: 0,
      failed: 0,
      accepted: 0,
      invalidUsers: 0,
      rootAttempts: 0,
      users: [],
      userSet: new Set<string>(),
      firstSeen: event.timestamp,
      lastSeen: event.timestamp,
    };

    current.total += 1;
    current.lastSeen = event.timestamp;
    if (event.eventType === 'failed') current.failed += 1;
    if (event.eventType === 'accepted') current.accepted += 1;
    if (event.invalidUser) current.invalidUsers += 1;
    if (event.username === 'root' && event.eventType !== 'accepted') {
      current.rootAttempts += 1;
    }
    if (event.username) current.userSet.add(event.username);
    summaries.set(event.sourceIp, current);
  });

  return [...summaries.values()]
    .map(({ userSet, ...summary }) => {
      const withUsers = { ...summary, users: [...userSet] };
      const trusted = trustedIps.has(withUsers.ip.toLowerCase());
      return { ...withUsers, ...calculateRisk(withUsers, policy, trusted) };
    })
    .sort((first, second) => {
      return second.score - first.score || second.failed - first.failed || second.total - first.total;
    });
}

function riskClass(risk: RiskLevel) {
  if (risk === 'Wysokie') {
    return 'border-rose-400/25 bg-rose-400/10 text-rose-200';
  }
  if (risk === 'Średnie') {
    return 'border-amber-400/25 bg-amber-400/10 text-amber-100';
  }
  return 'border-emerald-400/25 bg-emerald-400/10 text-emerald-200';
}

function csvValue(value?: string | number | boolean) {
  const output = value === undefined ? '' : String(value);
  return '"' + output.replaceAll('"', '""') + '"';
}

function escapeHtml(value?: string | number) {
  const entities: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return String(value ?? '').replace(/[&<>"']/g, (character) => entities[character]);
}

function downloadText(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function createSnapshot(
  events: AuthEvent[],
  sourceName: string,
  policy: SecurityPolicy,
  blocked: number,
): HistorySnapshot {
  const summaries = makeIpSummaries(events, policy);
  return {
    id: Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8),
    createdAt: new Date().toISOString(),
    sourceName,
    total: events.length,
    failed: events.filter((event) => event.eventType === 'failed').length,
    accepted: events.filter((event) => event.eventType === 'accepted').length,
    suspicious: summaries.filter((summary) => summary.risk !== 'Niskie').length,
    uniqueIps: summaries.length,
    blocked,
  };
}

function formatSnapshotDate(value: string) {
  return new Intl.DateTimeFormat('pl-PL', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value));
}

function makeReportHtml(
  snapshot: HistorySnapshot,
  summaries: IpSummary[],
  blocklist: BlockedIp[],
) {
  const riskRows = summaries
    .slice(0, 15)
    .map((summary) => {
      return (
        '<tr><td>' +
        escapeHtml(summary.ip) +
        '</td><td>' +
        summary.failed +
        '</td><td>' +
        summary.accepted +
        '</td><td>' +
        escapeHtml(summary.users.join(', ') || '—') +
        '</td><td>' +
        escapeHtml(summary.risk) +
        '</td></tr>'
      );
    })
    .join('');
  const blockedRows = blocklist.length
    ? blocklist
        .map((entry) => {
          return (
            '<li><strong>' +
            escapeHtml(entry.ip) +
            '</strong> — ' +
            escapeHtml(entry.reason) +
            ' (' +
            escapeHtml(formatSnapshotDate(entry.addedAt)) +
            ')</li>'
          );
        })
        .join('')
    : '<li>Brak adresów na lokalnej liście blokad.</li>';

  return [
    '<!doctype html><html lang="pl"><head><meta charset="utf-8"><title>System Guard — raport SSH</title>',
    '<style>body{font-family:Arial,sans-serif;color:#172033;margin:40px;line-height:1.45}h1{margin:0;color:#0b3555}h2{margin-top:34px;color:#0b3555}.lead{color:#536176}table{width:100%;border-collapse:collapse;margin-top:12px}th,td{padding:9px 10px;border-bottom:1px solid #dce3eb;text-align:left;font-size:13px}th{background:#eef7fb}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}.metric{border:1px solid #dce3eb;border-radius:10px;padding:14px}.metric b{display:block;font-size:25px;color:#0b3555}.muted{color:#637086;font-size:12px}@media print{body{margin:20px}.metrics{gap:8px}}</style></head><body>',
    '<h1>System Guard — raport SSH</h1><p class="lead">Wygenerowano: ' +
      escapeHtml(formatSnapshotDate(snapshot.createdAt)) +
      ' · Źródło: ' +
      escapeHtml(snapshot.sourceName) +
      '</p>',
    '<section class="metrics"><div class="metric"><span>Nieudane logowania</span><b>' +
      snapshot.failed +
      '</b></div><div class="metric"><span>Udane logowania</span><b>' +
      snapshot.accepted +
      '</b></div><div class="metric"><span>Podejrzane IP</span><b>' +
      snapshot.suspicious +
      '</b></div><div class="metric"><span>Unikalne IP</span><b>' +
      snapshot.uniqueIps +
      '</b></div></section>',
    '<h2>Adresy wymagające uwagi</h2><table><thead><tr><th>Adres IP</th><th>Odrzucone</th><th>Udane</th><th>Cele</th><th>Ryzyko</th></tr></thead><tbody>' +
      (riskRows || '<tr><td colspan="5">Brak danych.</td></tr>') +
      '</tbody></table>',
    '<h2>Lokalna lista blokad</h2><ul>' +
      blockedRows +
      '</ul><p class="muted">Raport nie wykonuje blokad automatycznie. Zweryfikuj adresy IP przed użyciem poleceń zapory.</p>',
    '</body></html>',
  ].join('');
}

function MetricCard({
  label,
  value,
  detail,
  accent,
}: {
  label: string;
  value: string | number;
  detail: string;
  accent: string;
}) {
  return (
    <article className="rounded-2xl border border-white/8 bg-white/[0.035] p-4 shadow-[0_20px_50px_rgba(0,0,0,0.12)] backdrop-blur-sm">
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm font-medium text-slate-300">{label}</p>
        <span className={'mt-1 h-2.5 w-2.5 rounded-full ' + accent} aria-hidden="true" />
      </div>
      <p className="mt-4 text-3xl font-semibold tracking-tight text-white">{value}</p>
      <p className="mt-2 text-xs leading-5 text-slate-500">{detail}</p>
    </article>
  );
}

export default function Home() {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [events, setEvents] = useState<AuthEvent[]>(() => parseAuthLog(SAMPLE_LOG));
  const [fileName, setFileName] = useState('Dane demonstracyjne');
  const [policy, setPolicy] = useState<SecurityPolicy>(DEFAULT_POLICY);
  const [history, setHistory] = useState<HistorySnapshot[]>([]);
  const [blocklist, setBlocklist] = useState<BlockedIp[]>([]);
  const [alertSettings, setAlertSettings] =
    useState<AlertSettings>(DEFAULT_ALERT_SETTINGS);
  const [monitorSettings, setMonitorSettings] =
    useState<MonitorSettings>(DEFAULT_MONITOR_SETTINGS);
  const [monitorEnabled, setMonitorEnabled] = useState(false);
  const [monitorStatus, setMonitorStatus] =
    useState<MonitorStatus>('zatrzymany');
  const [storageReady, setStorageReady] = useState(false);
  const [query, setQuery] = useState('');
  const [eventFilter, setEventFilter] = useState<EventFilter>('all');
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [selectedIp, setSelectedIp] = useState<string | null>(null);

  useEffect(() => {
    const restoreLocalState = () => {
      try {
        const storedHistory = localStorage.getItem(STORAGE_KEYS.history);
        const storedBlocklist = localStorage.getItem(STORAGE_KEYS.blocklist);
        const storedPolicy = localStorage.getItem(STORAGE_KEYS.policy);
        const storedAlerts = localStorage.getItem(STORAGE_KEYS.alerts);
        const storedMonitor = localStorage.getItem(STORAGE_KEYS.monitor);

        if (storedHistory) setHistory(JSON.parse(storedHistory) as HistorySnapshot[]);
        if (storedBlocklist) setBlocklist(JSON.parse(storedBlocklist) as BlockedIp[]);
        if (storedPolicy) {
          setPolicy((current) => ({
            ...current,
            ...(JSON.parse(storedPolicy) as Partial<SecurityPolicy>),
          }));
        }
        if (storedAlerts) {
          setAlertSettings((current) => ({
            ...current,
            ...(JSON.parse(storedAlerts) as Partial<AlertSettings>),
            slackWebhook: '',
          }));
        }
        if (storedMonitor) {
          setMonitorSettings((current) => ({
            ...current,
            ...(JSON.parse(storedMonitor) as Partial<MonitorSettings>),
          }));
        }
      } catch {
        setError('Nie udało się odczytać części lokalnych ustawień. Możesz nadal korzystać z analizy.');
      } finally {
        setStorageReady(true);
      }
    };
    const restoreTimer = window.setTimeout(restoreLocalState, 0);
    return () => window.clearTimeout(restoreTimer);
  }, []);

  useEffect(() => {
    if (!storageReady) return;
    localStorage.setItem(STORAGE_KEYS.history, JSON.stringify(history.slice(0, 90)));
  }, [history, storageReady]);

  useEffect(() => {
    if (!storageReady) return;
    localStorage.setItem(STORAGE_KEYS.blocklist, JSON.stringify(blocklist));
  }, [blocklist, storageReady]);

  useEffect(() => {
    if (!storageReady) return;
    localStorage.setItem(STORAGE_KEYS.policy, JSON.stringify(policy));
  }, [policy, storageReady]);

  useEffect(() => {
    if (!storageReady) return;
    localStorage.setItem(
      STORAGE_KEYS.alerts,
      JSON.stringify({
        browser: alertSettings.browser,
        emailAddress: alertSettings.emailAddress,
        slackAutomatic: alertSettings.slackAutomatic,
      }),
    );
  }, [
    alertSettings.browser,
    alertSettings.emailAddress,
    alertSettings.slackAutomatic,
    storageReady,
  ]);

  useEffect(() => {
    if (!storageReady) return;
    localStorage.setItem(STORAGE_KEYS.monitor, JSON.stringify(monitorSettings));
  }, [monitorSettings, storageReady]);

  useEffect(() => {
    if (!monitorEnabled) {
      return;
    }

    const endpoint = monitorSettings.endpoint.trim();
    if (!endpoint) {
      return;
    }

    let cancelled = false;
    const poll = async () => {
      try {
        setMonitorStatus('łączenie');
        const response = await fetch(endpoint, { cache: 'no-store' });
        if (!response.ok) throw new Error('Monitor zwrócił błąd');
        const payload = (await response.json()) as { lines?: unknown };
        const lines = Array.isArray(payload.lines)
          ? payload.lines.filter((line): line is string => typeof line === 'string')
          : [];

        if (cancelled) return;
        setMonitorStatus('aktywny');
        if (!lines.length) return;

        const batchId = Date.now().toString(36);
        const appended = parseAuthLog(lines.join('\n'))
          .filter((event) => event.eventType !== 'unknown')
          .map((event, index) => ({
            ...event,
            id: 'live-' + batchId + '-' + index + '-' + event.rawLine,
          }));
        if (!appended.length) return;

        setEvents((current) => [...current, ...appended].slice(-5000));
        setFileName('Monitor lokalny');
        setNotice('Monitor dodał ' + appended.length + ' nowych zdarzeń SSH.');

        if (
          alertSettings.browser &&
          'Notification' in window &&
          Notification.permission === 'granted' &&
          appended.some((event) => event.eventType === 'failed')
        ) {
          new Notification('System Guard: nowe zdarzenia SSH', {
            body: 'Dodano ' + appended.length + ' wpisów z lokalnego monitora.',
          });
        }
      } catch {
        if (!cancelled) setMonitorStatus('błąd');
      }
    };

    void poll();
    const interval = window.setInterval(
      () => void poll(),
      Math.max(3, monitorSettings.intervalSeconds) * 1000,
    );
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [
    alertSettings.browser,
    monitorEnabled,
    monitorSettings.endpoint,
    monitorSettings.intervalSeconds,
  ]);

  const ipSummaries = useMemo(
    () => makeIpSummaries(events, policy),
    [events, policy],
  );
  const riskByIp = useMemo(
    () => new Map(ipSummaries.map((summary) => [summary.ip, summary.risk])),
    [ipSummaries],
  );

  const metrics = useMemo(() => {
    const failed = events.filter((event) => event.eventType === 'failed').length;
    const accepted = events.filter((event) => event.eventType === 'accepted').length;
    const invalidUsers = new Set(
      events
        .filter((event) => event.invalidUser)
        .map((event) => event.username)
        .filter(Boolean),
    ).size;
    const suspicious = ipSummaries.filter((summary) => summary.risk !== 'Niskie').length;
    return {
      failed,
      accepted,
      invalidUsers,
      suspicious,
      uniqueIps: ipSummaries.length,
    };
  }, [events, ipSummaries]);

  const timeline = useMemo(() => {
    const buckets = new Map<string, { failed: number; accepted: number; closed: number }>();
    events.forEach((event) => {
      const match = event.timestamp.match(/(\d{2}):\d{2}:\d{2}$/);
      if (!match) return;
      const hour = match[1] + ':00';
      const current = buckets.get(hour) ?? { failed: 0, accepted: 0, closed: 0 };
      if (event.eventType === 'failed' || event.eventType === 'invalid_user') {
        current.failed += 1;
      }
      if (event.eventType === 'accepted') current.accepted += 1;
      if (event.eventType === 'connection_closed') current.closed += 1;
      buckets.set(hour, current);
    });
    return [...buckets.entries()]
      .sort(([first], [second]) => first.localeCompare(second))
      .map(([hour, values]) => ({ hour, ...values }));
  }, [events]);

  const maxTimelineValue = Math.max(
    1,
    ...timeline.map((item) => item.failed + item.accepted + item.closed),
  );

  const filteredEvents = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return events.filter((event) => {
      if (eventFilter !== 'all' && event.eventType !== eventFilter) return false;
      if (riskFilter !== 'all') {
        const risk = event.sourceIp ? riskByIp.get(event.sourceIp) : 'Niskie';
        if (riskFilter === 'high' && risk !== 'Wysokie') return false;
        if (riskFilter === 'medium' && risk === 'Niskie') return false;
      }
      if (!normalizedQuery) return true;
      return [event.timestamp, event.sourceIp, event.username, event.authMethod, event.rawLine]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
        .includes(normalizedQuery);
    });
  }, [eventFilter, events, query, riskByIp, riskFilter]);

  const selectedSummary = selectedIp
    ? ipSummaries.find((summary) => summary.ip === selectedIp)
    : undefined;
  const selectedEvents = selectedIp
    ? events.filter((event) => event.sourceIp === selectedIp)
    : [];
  const previousSnapshot = history.length > 1 ? history[1] : undefined;
  const latestSnapshot = history[0];
  const currentMonitorStatus: MonitorStatus = !monitorEnabled
    ? 'zatrzymany'
    : !monitorSettings.endpoint.trim()
      ? 'błąd'
      : monitorStatus;

  function showNotice(message: string, timeout = 4000) {
    setNotice(message);
    window.setTimeout(() => setNotice(''), timeout);
  }

  function saveSnapshot(analyzedEvents: AuthEvent[], sourceName: string) {
    const snapshot = createSnapshot(
      analyzedEvents,
      sourceName,
      policy,
      blocklist.length,
    );
    setHistory((current) => [snapshot, ...current].slice(0, 90));
    return snapshot;
  }

  function notifyAboutHighRisk(
    summaries: IpSummary[],
    sourceName: string,
  ) {
    const highRisk = summaries.filter((summary) => summary.risk === 'Wysokie');
    if (!highRisk.length) return;
    if (
      alertSettings.browser &&
      'Notification' in window &&
      Notification.permission === 'granted'
    ) {
      new Notification('System Guard: wysokie ryzyko', {
        body:
          sourceName +
          ': wykryto ' +
          highRisk.length +
          ' adres(y) IP o wysokim ryzyku.',
      });
    }
    if (alertSettings.slackAutomatic && alertSettings.slackWebhook.trim()) {
      void sendSlackAlert(sourceName, highRisk, false);
    }
  }

  function analyzeText(content: string, name: string) {
    const parsed = parseAuthLog(content);
    const recognized = parsed.filter((event) => event.eventType !== 'unknown').length;
    if (!content.trim()) {
      setError('Plik jest pusty. Wybierz plik z wpisami SSH.');
      return;
    }
    if (!recognized) {
      setError(
        'Nie rozpoznaliśmy wpisów SSH w tym pliku. Wczytaj auth.log, secure lub plik tekstowy z wpisami sshd.',
      );
      return;
    }

    setEvents(parsed);
    setFileName(name);
    setError('');
    setSelectedIp(null);
    const summaries = makeIpSummaries(parsed, policy);
    saveSnapshot(parsed, name);
    notifyAboutHighRisk(summaries, name);
    showNotice('Przeanalizowano ' + parsed.length + ' wpisów, z czego ' + recognized + ' rozpoznano jako zdarzenia SSH.', 5000);
  }

  function readLogFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => analyzeText(String(reader.result ?? ''), file.name);
    reader.onerror = () => setError('Nie udało się odczytać wybranego pliku. Spróbuj ponownie.');
    reader.readAsText(file);
  }

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (file) readLogFile(file);
  }

  function handleDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    setIsDragging(false);
    const file = event.dataTransfer.files?.[0];
    if (file) readLogFile(file);
  }

  function restoreDemo() {
    setEvents(parseAuthLog(SAMPLE_LOG));
    setFileName('Dane demonstracyjne');
    setError('');
    setSelectedIp(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
    showNotice('Przywrócono przykładowy zestaw zdarzeń.');
  }

  function exportCsv() {
    const header = [
      'Czas',
      'Host',
      'PID',
      'Typ zdarzenia',
      'Metoda',
      'Użytkownik',
      'Adres IP',
      'Port',
      'Preauth',
      'Surowy wpis',
    ];
    const rows = filteredEvents.map((event) => [
      event.timestamp,
      event.hostname,
      event.pid,
      EVENT_META[event.eventType].label,
      event.authMethod,
      event.username,
      event.sourceIp,
      event.sourcePort,
      event.preauth ? 'tak' : 'nie',
      event.rawLine,
    ]);
    const csv = [header, ...rows]
      .map((row) => row.map(csvValue).join(','))
      .join('\n');
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'ssh-guard-report.csv';
    anchor.click();
    URL.revokeObjectURL(url);
    showNotice('Pobrano raport CSV z aktualnie widocznymi zdarzeniami.');
  }

  function exportHtmlReport() {
    const snapshot = createSnapshot(events, fileName, policy, blocklist.length);
    const html = makeReportHtml(snapshot, ipSummaries, blocklist);
    downloadText(
      'system-guard-ssh-report.html',
      html,
      'text/html;charset=utf-8',
    );
    showNotice('Pobrano samodzielny raport HTML.');
  }

  function printPdfReport() {
    const snapshot = createSnapshot(events, fileName, policy, blocklist.length);
    const reportWindow = window.open('', '_blank');
    if (!reportWindow) {
      showNotice('Przeglądarka zablokowała okno raportu. Zezwól na wyskakujące okna i spróbuj ponownie.');
      return;
    }
    reportWindow.opener = null;
    reportWindow.document.open();
    reportWindow.document.write(makeReportHtml(snapshot, ipSummaries, blocklist));
    reportWindow.document.close();
    reportWindow.focus();
    window.setTimeout(() => reportWindow.print(), 250);
  }

  function addToBlocklist(summary: IpSummary) {
    if (blocklist.some((entry) => entry.ip === summary.ip)) {
      showNotice('Ten adres IP jest już na lokalnej liście blokad.');
      return;
    }
    setBlocklist((current) => [
      {
        ip: summary.ip,
        reason:
          summary.risk +
          ' ryzyko · ' +
          summary.failed +
          ' odrzuconych prób',
        addedAt: new Date().toISOString(),
        failed: summary.failed,
        risk: summary.risk,
      },
      ...current,
    ]);
    showNotice('Dodano ' + summary.ip + ' do lokalnej listy blokad. Żadna zapora nie została zmieniona automatycznie.');
  }

  function removeFromBlocklist(ip: string) {
    setBlocklist((current) => current.filter((entry) => entry.ip !== ip));
    showNotice('Usunięto ' + ip + ' z lokalnej listy blokad.');
  }

  function exportFail2ban() {
    if (!blocklist.length) {
      showNotice('Lista blokad jest pusta. Najpierw dodaj adres IP z poziomu szczegółów.');
      return;
    }
    const commands = [
      '#!/usr/bin/env bash',
      '# Wygenerowano przez System Guard. Zweryfikuj adresy przed uruchomieniem.',
      'set -euo pipefail',
      '',
      ...blocklist.map(
        (entry) => 'sudo fail2ban-client set sshd banip ' + entry.ip,
      ),
      '',
    ].join('\n');
    downloadText(
      'system-guard-fail2ban-banip.sh',
      commands,
      'text/x-shellscript;charset=utf-8',
    );
    showNotice('Pobrano skrypt Fail2ban. Nie został automatycznie uruchomiony.');
  }

  async function enableBrowserAlerts() {
    if (!('Notification' in window)) {
      showNotice('Ta przeglądarka nie obsługuje powiadomień systemowych.');
      return;
    }
    const permission = await Notification.requestPermission();
    const enabled = permission === 'granted';
    setAlertSettings((current) => ({ ...current, browser: enabled }));
    showNotice(
      enabled
        ? 'Powiadomienia systemowe są włączone.'
        : 'Nie przyznano zgody na powiadomienia systemowe.',
    );
  }

  function composeEmailAlert() {
    const recipient = alertSettings.emailAddress.trim();
    if (!recipient) {
      showNotice('Wpisz adres e-mail w ustawieniach alertów.');
      return;
    }
    const highRisk = ipSummaries.filter((summary) => summary.risk === 'Wysokie');
    const subject = encodeURIComponent(
      'System Guard: ' + highRisk.length + ' adres(y) IP o wysokim ryzyku',
    );
    const body = encodeURIComponent(
      [
        'Raport System Guard',
        '',
        'Źródło: ' + fileName,
        'Nieudane logowania: ' + metrics.failed,
        'Podejrzane IP: ' + metrics.suspicious,
        'Adresy wysokiego ryzyka: ' +
          (highRisk.map((summary) => summary.ip).join(', ') || 'brak'),
      ].join('\n'),
    );
    window.location.href =
      'mailto:' + encodeURIComponent(recipient) + '?subject=' + subject + '&body=' + body;
  }

  async function sendSlackAlert(
    sourceName: string,
    highRisk: IpSummary[],
    showFeedback: boolean,
  ) {
    const webhook = alertSettings.slackWebhook.trim();
    if (!webhook) {
      if (showFeedback) {
        showNotice('Wpisz adres webhooka Slack. Jest przechowywany tylko do końca bieżącej sesji.');
      }
      return;
    }
    try {
      await fetch(webhook, {
        method: 'POST',
        mode: 'no-cors',
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
        body: JSON.stringify({
          text:
            'System Guard — alert SSH\nŹródło: ' +
            sourceName +
            '\nWysokie ryzyko: ' +
            (highRisk.map((summary) => summary.ip).join(', ') || 'brak'),
        }),
      });
      if (showFeedback) {
        showNotice('Wysłano żądanie testowego alertu do Slacka. Przeglądarka nie może potwierdzić dostarczenia odpowiedzi.');
      }
    } catch {
      if (showFeedback) {
        showNotice('Nie udało się wysłać żądania do Slacka. Sprawdź adres webhooka oraz połączenie sieciowe.');
      }
    }
  }

  async function sendSlackTest() {
    await sendSlackAlert(
      'test ręczny',
      ipSummaries.filter((summary) => summary.risk === 'Wysokie'),
      true,
    );
  }

  async function copyFirewallRules() {
    const candidates = ipSummaries.filter((summary) => summary.risk === 'Wysokie');
    const rules = candidates.length
      ? candidates.map((summary) => 'sudo ufw deny from ' + summary.ip).join('\n')
      : '# Brak adresów IP o wysokim ryzyku w aktualnym zestawie danych.';

    try {
      await navigator.clipboard.writeText(rules);
      showNotice(
        'Skopiowano ostrożne reguły UFW dla adresów o wysokim ryzyku. Zweryfikuj je przed użyciem.',
        5000,
      );
    } catch {
      showNotice('Nie udało się skopiować reguł. Wybierz adres IP z tabeli i skopiuj go ręcznie.');
    }
  }

  return (
    <main className="min-h-screen overflow-x-hidden bg-[#050b13] text-slate-100">
      <div className="pointer-events-none fixed inset-0 overflow-hidden" aria-hidden="true">
        <div className="absolute -left-40 -top-48 h-[38rem] w-[38rem] rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="absolute right-[-14rem] top-20 h-[34rem] w-[34rem] rounded-full bg-indigo-500/10 blur-3xl" />
      </div>

      <div className="relative mx-auto max-w-[1480px] px-4 pb-12 pt-5 sm:px-6 lg:px-8">
        <header className="flex flex-col gap-4 border-b border-white/8 pb-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl border border-cyan-300/25 bg-cyan-300/10 text-sm font-black tracking-tight text-cyan-100 shadow-[0_0_28px_rgba(34,211,238,0.14)]">
              SG
            </div>
            <div>
              <p className="text-sm font-semibold tracking-tight text-white">System Guard</p>
              <p className="text-xs text-slate-500">SSH Log Analyzer</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="inline-flex items-center gap-2 rounded-full border border-emerald-400/15 bg-emerald-400/8 px-3 py-1.5 text-emerald-100">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-300 shadow-[0_0_10px_rgba(110,231,183,0.9)]" />
              Analiza lokalna
            </span>
            <button
              type="button"
              onClick={restoreDemo}
              className="rounded-full border border-white/10 px-3 py-1.5 text-slate-300 transition hover:border-cyan-300/35 hover:bg-cyan-300/8 hover:text-white"
            >
              Przywróć demo
            </button>
          </div>
        </header>

        <section className="grid gap-6 py-8 xl:grid-cols-[minmax(0,1fr)_390px] xl:items-end">
          <div>
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-cyan-300/15 bg-cyan-300/8 px-3 py-1 text-xs font-medium text-cyan-100">
                Bez wysyłania logów na serwer
              </span>
              <span className="text-xs text-slate-500">Źródło: {fileName}</span>
            </div>
            <h1 className="max-w-3xl text-3xl font-semibold tracking-[-0.04em] text-white sm:text-5xl">
              Zobacz, kto próbuje dostać się do Twojego serwera.
            </h1>
            <p className="mt-4 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">
              Wczytaj plik <code className="rounded bg-white/7 px-1.5 py-0.5 text-slate-300">auth.log</code> lub{' '}
              <code className="rounded bg-white/7 px-1.5 py-0.5 text-slate-300">secure</code>. Aplikacja wykrywa udane i nieudane logowania, konta nieistniejące oraz serie prób brute-force.
            </p>
          </div>

          <label
            onDragOver={(event) => {
              event.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            className={[
              'group flex min-h-40 cursor-pointer flex-col justify-between rounded-2xl border p-5 transition',
              isDragging
                ? 'border-cyan-300/70 bg-cyan-300/10 shadow-[0_0_42px_rgba(34,211,238,0.15)]'
                : 'border-white/10 bg-white/[0.035] hover:border-cyan-300/35 hover:bg-cyan-300/[0.055]',
            ].join(' ')}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".log,.txt,text/plain"
              onChange={handleFileChange}
              className="sr-only"
            />
            <div className="flex items-start justify-between gap-4">
              <div className="grid h-10 w-10 place-items-center rounded-xl bg-white/7 text-lg text-cyan-200">↥</div>
              <span className="rounded-full border border-white/10 px-2.5 py-1 text-[11px] text-slate-400">auth.log · secure · .txt</span>
            </div>
            <div>
              <p className="font-medium text-white">Wczytaj log SSH</p>
              <p className="mt-1 text-sm text-slate-500">Przeciągnij plik tutaj albo wybierz go z dysku.</p>
            </div>
          </label>
        </section>

        {error && (
          <div role="alert" className="mb-6 rounded-xl border border-rose-400/25 bg-rose-400/10 px-4 py-3 text-sm text-rose-100">
            {error}
          </div>
        )}
        {notice && (
          <div role="status" className="mb-6 rounded-xl border border-cyan-300/20 bg-cyan-300/8 px-4 py-3 text-sm text-cyan-50">
            {notice}
          </div>
        )}

        <section aria-label="Podsumowanie bezpieczeństwa" className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard label="Nieudane logowania" value={metrics.failed} detail="Wpisy Failed password i Failed publickey" accent="bg-rose-300" />
          <MetricCard label="Udane logowania" value={metrics.accepted} detail="Zdarzenia Accepted dla haseł i kluczy" accent="bg-emerald-300" />
          <MetricCard label="Podejrzane adresy IP" value={metrics.suspicious} detail="Średnie lub wysokie ryzyko" accent="bg-amber-300" />
          <MetricCard label="Rozpoznane obce konta" value={metrics.invalidUsers} detail="Nazwy kont widoczne w próbach" accent="bg-cyan-300" />
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-2">
          <article className="rounded-2xl border border-white/8 bg-white/[0.035] p-5 sm:p-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-sm font-semibold text-white">Raport dla zespołu</p>
                <p className="mt-1 text-sm leading-6 text-slate-500">Pobierz samodzielny raport HTML albo otwórz wersję gotową do zapisania jako PDF.</p>
              </div>
              <span className="w-fit rounded-full border border-cyan-300/15 bg-cyan-300/8 px-2.5 py-1 text-[11px] text-cyan-100">bez danych poza przeglądarką</span>
            </div>
            <div className="mt-5 flex flex-wrap gap-3">
              <button type="button" onClick={exportHtmlReport} className="rounded-xl border border-white/10 bg-white/[0.045] px-4 py-2.5 text-sm font-medium text-white transition hover:border-cyan-300/40 hover:bg-cyan-300/10">
                Pobierz HTML
              </button>
              <button type="button" onClick={printPdfReport} className="rounded-xl bg-cyan-200 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-white">
                Drukuj / zapisz PDF
              </button>
            </div>
            <p className="mt-4 text-xs leading-5 text-slate-500">Raport zawiera podsumowanie, ranking adresów IP oraz lokalną listę blokad — bez pełnej treści surowych logów.</p>
          </article>

          <article className="rounded-2xl border border-white/8 bg-white/[0.035] p-5 sm:p-6">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-sm font-semibold text-white">Historia i porównanie</p>
                <p className="mt-1 text-sm leading-6 text-slate-500">Zapamiętywane są wyłącznie statystyki analiz na tym urządzeniu, a nie pełne logi.</p>
              </div>
              <span className="rounded-full bg-white/6 px-2.5 py-1 text-[11px] text-slate-400">{history.length} zapisów</span>
            </div>

            {latestSnapshot ? (
              <div className="mt-5">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div className="rounded-xl bg-black/15 p-3"><p className="text-[11px] text-slate-500">Odrzucone</p><p className="mt-1 text-lg font-semibold text-rose-200">{latestSnapshot.failed}</p></div>
                  <div className="rounded-xl bg-black/15 p-3"><p className="text-[11px] text-slate-500">Podejrzane IP</p><p className="mt-1 text-lg font-semibold text-amber-100">{latestSnapshot.suspicious}</p></div>
                  <div className="rounded-xl bg-black/15 p-3"><p className="text-[11px] text-slate-500">Unikalne IP</p><p className="mt-1 text-lg font-semibold text-white">{latestSnapshot.uniqueIps}</p></div>
                  <div className="rounded-xl bg-black/15 p-3"><p className="text-[11px] text-slate-500">Zablokowane</p><p className="mt-1 text-lg font-semibold text-cyan-100">{latestSnapshot.blocked}</p></div>
                </div>
                {previousSnapshot ? (
                  <p className="mt-4 rounded-lg border border-white/8 bg-white/[0.025] px-3 py-2.5 text-xs leading-5 text-slate-400">
                    W porównaniu z poprzednią analizą: nieudane logowania {latestSnapshot.failed - previousSnapshot.failed >= 0 ? '+' : ''}{latestSnapshot.failed - previousSnapshot.failed}, podejrzane IP {latestSnapshot.suspicious - previousSnapshot.suspicious >= 0 ? '+' : ''}{latestSnapshot.suspicious - previousSnapshot.suspicious}. Poprzednia analiza: {formatSnapshotDate(previousSnapshot.createdAt)}.
                  </p>
                ) : (
                  <p className="mt-4 text-xs leading-5 text-slate-500">Wczytaj kolejny plik w innym dniu, aby zobaczyć porównanie trendu.</p>
                )}
                <div className="mt-4 max-h-28 space-y-1.5 overflow-auto pr-1">
                  {history.slice(0, 4).map((snapshot) => (
                    <div key={snapshot.id} className="flex items-center justify-between gap-3 text-xs text-slate-500">
                      <span className="truncate">{formatSnapshotDate(snapshot.createdAt)} · {snapshot.sourceName}</span>
                      <span className="shrink-0 text-slate-300">{snapshot.failed} błędów</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="mt-5 rounded-xl border border-dashed border-white/10 px-4 py-5 text-sm leading-6 text-slate-500">
                Pierwszy wpis historii zostanie utworzony po wczytaniu własnego pliku logów.
              </div>
            )}
          </article>
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-2">
          <article className="rounded-2xl border border-white/8 bg-white/[0.035] p-5 sm:p-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-sm font-semibold text-white">Lokalna lista blokad</p>
                <p className="mt-1 text-sm leading-6 text-slate-500">Dodanie adresu nie zmienia zapory. Gdy lista będzie gotowa, pobierz bezpieczny skrypt do ręcznej weryfikacji i użycia w Fail2ban.</p>
              </div>
              <button type="button" onClick={exportFail2ban} className="shrink-0 rounded-xl border border-rose-300/20 bg-rose-300/8 px-3 py-2 text-xs font-medium text-rose-100 transition hover:bg-rose-300/15">
                Eksport Fail2ban
              </button>
            </div>
            <div className="mt-5 space-y-2">
              {blocklist.length ? blocklist.slice(0, 5).map((entry) => (
                <div key={entry.ip} className="flex items-center gap-3 rounded-xl border border-white/8 bg-black/15 px-3 py-3">
                  <span className="h-2 w-2 rounded-full bg-rose-300" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-sm text-white">{entry.ip}</span>
                    <span className="mt-0.5 block truncate text-xs text-slate-500">{entry.reason}</span>
                  </span>
                  <button type="button" onClick={() => removeFromBlocklist(entry.ip)} className="text-xs text-slate-400 underline decoration-slate-600 underline-offset-4 hover:text-white">
                    Usuń
                  </button>
                </div>
              )) : (
                <div className="rounded-xl border border-dashed border-white/10 px-4 py-5 text-sm leading-6 text-slate-500">
                  Lista jest pusta. Otwórz szczegóły adresu IP z rankingu i dodaj go po weryfikacji.
                </div>
              )}
            </div>
          </article>

          <article className="rounded-2xl border border-white/8 bg-white/[0.035] p-5 sm:p-6">
            <div>
              <p className="text-sm font-semibold text-white">Powiadomienia</p>
              <p className="mt-1 text-sm leading-6 text-slate-500">Powiadomienia systemowe działają automatycznie po wykryciu wysokiego ryzyka. Slack można włączyć dopiero po podaniu webhooka i wyrażeniu zgody.</p>
            </div>
            <div className="mt-5 grid gap-3 sm:grid-cols-[auto_minmax(0,1fr)] sm:items-center">
              <button type="button" onClick={enableBrowserAlerts} className="rounded-xl border border-cyan-300/20 bg-cyan-300/8 px-3 py-2.5 text-sm font-medium text-cyan-100 transition hover:bg-cyan-300/15">
                {alertSettings.browser ? 'Powiadomienia włączone' : 'Włącz powiadomienia'}
              </button>
              <p className="text-xs leading-5 text-slate-500">Stan: {alertSettings.browser ? 'aktywny' : 'wyłączony lub bez zgody przeglądarki'}.</p>
            </div>
            <div className="mt-4 grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]">
              <input
                value={alertSettings.emailAddress}
                onChange={(event) => setAlertSettings((current) => ({ ...current, emailAddress: event.target.value }))}
                type="email"
                placeholder="adres@firma.pl"
                aria-label="Adres e-mail dla alertu"
                className="min-w-0 rounded-xl border border-white/10 bg-black/15 px-3 py-2.5 text-sm text-white outline-none placeholder:text-slate-600 focus:border-cyan-300/50"
              />
              <button type="button" onClick={composeEmailAlert} className="rounded-xl border border-white/10 px-3 py-2.5 text-sm text-slate-200 transition hover:border-cyan-300/35 hover:text-white">
                Utwórz e-mail
              </button>
            </div>
            <div className="mt-3 grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]">
              <input
                value={alertSettings.slackWebhook}
                onChange={(event) => setAlertSettings((current) => ({ ...current, slackWebhook: event.target.value }))}
                type="url"
                placeholder="https://hooks.slack.com/services/..."
                aria-label="Adres webhooka Slack"
                className="min-w-0 rounded-xl border border-white/10 bg-black/15 px-3 py-2.5 text-sm text-white outline-none placeholder:text-slate-600 focus:border-cyan-300/50"
              />
              <button type="button" onClick={sendSlackTest} className="rounded-xl border border-white/10 px-3 py-2.5 text-sm text-slate-200 transition hover:border-cyan-300/35 hover:text-white">
                Test Slack
              </button>
            </div>
            <label className="mt-3 flex items-start gap-3 rounded-xl border border-white/8 bg-black/15 px-3 py-3 text-xs leading-5 text-slate-400">
              <input
                type="checkbox"
                checked={alertSettings.slackAutomatic}
                onChange={(event) => setAlertSettings((current) => ({ ...current, slackAutomatic: event.target.checked }))}
                className="mt-0.5 h-4 w-4 accent-cyan-300"
              />
              <span>Wysyłaj alert Slack przy wykryciu wysokiego ryzyka. Adres webhooka musi pozostać wpisany w tej sesji.</span>
            </label>
            <p className="mt-3 text-xs leading-5 text-slate-500">Adres Slacka nie jest zapisywany w historii ani w plikach projektu — znika po zamknięciu bieżącej sesji.</p>
          </article>
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(360px,0.9fr)]">
          <article className="rounded-2xl border border-white/8 bg-white/[0.035] p-5 sm:p-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-sm font-semibold text-white">Monitor na żywo</p>
                <p className="mt-1 text-sm leading-6 text-slate-500">Połącz panel z dołączonym lokalnym agentem, który nasłuchuje zmian w <code className="rounded bg-white/7 px-1 text-slate-300">/var/log/auth.log</code>. Agent działa wyłącznie na <code className="rounded bg-white/7 px-1 text-slate-300">127.0.0.1</code>.</p>
              </div>
              <span className={['w-fit rounded-full border px-2.5 py-1 text-[11px] ', currentMonitorStatus === 'aktywny' ? 'border-emerald-400/20 bg-emerald-400/10 text-emerald-100' : currentMonitorStatus === 'błąd' ? 'border-rose-400/20 bg-rose-400/10 text-rose-100' : 'border-white/10 bg-white/5 text-slate-400'].join(' ')}>
                {currentMonitorStatus}
              </span>
            </div>
            <div className="mt-5 grid gap-3 sm:grid-cols-[minmax(0,1fr)_120px]">
              <input
                value={monitorSettings.endpoint}
                onChange={(event) => setMonitorSettings((current) => ({ ...current, endpoint: event.target.value }))}
                aria-label="Adres lokalnego monitora"
                className="min-w-0 rounded-xl border border-white/10 bg-black/15 px-3 py-2.5 font-mono text-sm text-white outline-none placeholder:text-slate-600 focus:border-cyan-300/50"
              />
              <label className="rounded-xl border border-white/10 bg-black/15 px-3 py-2 text-xs text-slate-500">
                co ile sekund
                <input
                  type="number"
                  min="3"
                  max="300"
                  value={monitorSettings.intervalSeconds}
                  onChange={(event) => setMonitorSettings((current) => ({ ...current, intervalSeconds: Math.max(3, Number(event.target.value) || 3)}))}
                  className="mt-1 w-full bg-transparent text-sm text-white outline-none"
                />
              </label>
            </div>
            <div className="mt-3 flex flex-wrap gap-3">
              <button type="button" onClick={() => { setMonitorStatus('łączenie'); setMonitorEnabled(true); }} disabled={monitorEnabled} className="rounded-xl bg-cyan-200 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-white disabled:cursor-not-allowed disabled:opacity-50">
                Uruchom odczyt
              </button>
              <button type="button" onClick={() => { setMonitorEnabled(false); setMonitorStatus('zatrzymany'); }} disabled={!monitorEnabled} className="rounded-xl border border-white/10 px-4 py-2.5 text-sm text-slate-300 transition hover:border-white/25 hover:text-white disabled:cursor-not-allowed disabled:opacity-50">
                Zatrzymaj
              </button>
            </div>
            <p className="mt-4 text-xs leading-5 text-slate-500">W repozytorium znajduje się skrypt <code className="text-slate-300">scripts/ssh-monitor.mjs</code>. W trybie monitorowania nie wysyłamy logów na zewnętrzny serwer.</p>
          </article>

          <article className="rounded-2xl border border-white/8 bg-white/[0.035] p-5 sm:p-6">
            <div>
              <p className="text-sm font-semibold text-white">Polityka bezpieczeństwa</p>
              <p className="mt-1 text-sm leading-6 text-slate-500">Dopasuj ocenę ryzyka do charakteru swojego serwera. Zaufane IP są wyłączone z alarmów.</p>
            </div>
            <div className="mt-5 grid grid-cols-3 gap-3">
              <label className="rounded-xl border border-white/10 bg-black/15 px-3 py-2 text-[11px] text-slate-500">
                wysokie od
                <input type="number" min="1" value={policy.highFailureThreshold} onChange={(event) => setPolicy((current) => ({ ...current, highFailureThreshold: Math.max(1, Number(event.target.value) || 1)}))} className="mt-1 w-full bg-transparent text-sm text-white outline-none" />
              </label>
              <label className="rounded-xl border border-white/10 bg-black/15 px-3 py-2 text-[11px] text-slate-500">
                średnie od
                <input type="number" min="1" value={policy.mediumFailureThreshold} onChange={(event) => setPolicy((current) => ({ ...current, mediumFailureThreshold: Math.max(1, Number(event.target.value) || 1)}))} className="mt-1 w-full bg-transparent text-sm text-white outline-none" />
              </label>
              <label className="rounded-xl border border-white/10 bg-black/15 px-3 py-2 text-[11px] text-slate-500">
                próby root
                <input type="number" min="1" value={policy.rootAttemptThreshold} onChange={(event) => setPolicy((current) => ({ ...current, rootAttemptThreshold: Math.max(1, Number(event.target.value) || 1)}))} className="mt-1 w-full bg-transparent text-sm text-white outline-none" />
              </label>
            </div>
            <label className="mt-3 block text-xs text-slate-500">
              Zaufane adresy IP — po jednym w wierszu lub po przecinku
              <textarea
                value={policy.trustedIps.join('\n')}
                onChange={(event) => setPolicy((current) => ({ ...current, trustedIps: event.target.value.split(/[\n,]/).map((ip) => ip.trim()).filter(Boolean) }))}
                placeholder="203.0.113.10"
                className="mt-1.5 min-h-20 w-full rounded-xl border border-white/10 bg-black/15 px-3 py-2.5 font-mono text-sm text-white outline-none placeholder:text-slate-600 focus:border-cyan-300/50"
              />
            </label>
            <label className="mt-3 block text-xs text-slate-500">
              Oczekiwani użytkownicy — wyłącznie do dokumentacji polityki
              <textarea
                value={policy.trustedUsers.join('\n')}
                onChange={(event) => setPolicy((current) => ({ ...current, trustedUsers: event.target.value.split(/[\n,]/).map((user) => user.trim()).filter(Boolean) }))}
                placeholder="deploy, admin"
                className="mt-1.5 min-h-16 w-full rounded-xl border border-white/10 bg-black/15 px-3 py-2.5 text-sm text-white outline-none placeholder:text-slate-600 focus:border-cyan-300/50"
              />
            </label>
          </article>
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.65fr)_minmax(340px,0.85fr)]">
          <article className="rounded-2xl border border-white/8 bg-white/[0.035] p-5 sm:p-6">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-sm font-semibold text-white">Aktywność w czasie</p>
                <p className="mt-1 text-sm text-slate-500">Czerwony: odrzucone lub nieznane konta · Zielony: udane logowania</p>
              </div>
              <span className="rounded-full bg-white/6 px-3 py-1.5 text-xs text-slate-400">{events.length} wpisów w analizie</span>
            </div>
            <div className="mt-7 flex min-h-52 items-end gap-3 overflow-x-auto pb-1">
              {timeline.length ? (
                timeline.map((item) => {
                  const total = item.failed + item.accepted + item.closed;
                  const totalHeight = Math.max(10, (total / maxTimelineValue) * 152);
                  const failedHeight = total ? Math.max(3, (item.failed / total) * totalHeight) : 0;
                  const acceptedHeight = total ? Math.max(3, (item.accepted / total) * totalHeight) : 0;
                  const closedHeight = Math.max(0, totalHeight - failedHeight - acceptedHeight);
                  return (
                    <div key={item.hour} className="flex min-w-14 flex-1 flex-col items-center gap-2">
                      <div
                        className="flex h-40 w-full max-w-12 flex-col justify-end overflow-hidden rounded-t-lg bg-white/[0.045]"
                        title={item.hour + ': ' + total + ' zdarzeń'}
                      >
                        {closedHeight > 0 && <div className="bg-sky-300/50" style={{ height: closedHeight + 'px' }} />}
                        {acceptedHeight > 0 && <div className="bg-emerald-300" style={{ height: acceptedHeight + 'px' }} />}
                        {failedHeight > 0 && <div className="bg-rose-300" style={{ height: failedHeight + 'px' }} />}
                      </div>
                      <span className="text-xs text-slate-500">{item.hour}</span>
                    </div>
                  );
                })
              ) : (
                <p className="text-sm text-slate-500">Brak zdarzeń z czasem, które można pokazać na osi.</p>
              )}
            </div>
          </article>

          <article className="rounded-2xl border border-white/8 bg-white/[0.035] p-5 sm:p-6">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-sm font-semibold text-white">Adresy wymagające uwagi</p>
                <p className="mt-1 text-sm text-slate-500">Ranking według liczby prób i wzorca ataku.</p>
              </div>
              <button
                type="button"
                onClick={copyFirewallRules}
                className="shrink-0 rounded-lg border border-rose-300/20 bg-rose-300/8 px-3 py-2 text-xs font-medium text-rose-100 transition hover:bg-rose-300/15"
              >
                Kopiuj reguły UFW
              </button>
            </div>
            <div className="mt-5 space-y-2">
              {ipSummaries.slice(0, 5).map((summary) => (
                <button
                  type="button"
                  key={summary.ip}
                  onClick={() => setSelectedIp(summary.ip)}
                  className="flex w-full items-center gap-3 rounded-xl border border-transparent px-3 py-3 text-left transition hover:border-white/10 hover:bg-white/[0.045] focus:outline-none focus-visible:border-cyan-300/60"
                >
                  <span
                    className={[
                      'h-2 w-2 shrink-0 rounded-full',
                      summary.risk === 'Wysokie'
                        ? 'bg-rose-300'
                        : summary.risk === 'Średnie'
                          ? 'bg-amber-300'
                          : 'bg-emerald-300',
                    ].join(' ')}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-sm text-slate-100">{summary.ip}</span>
                    <span className="mt-0.5 block text-xs text-slate-500">
                      {summary.failed} odrzuconych · {summary.users.slice(0, 3).join(', ') || 'brak konta'}
                    </span>
                  </span>
                  <span className={'rounded-full border px-2.5 py-1 text-[11px] font-medium ' + riskClass(summary.risk)}>
                    {summary.risk}
                  </span>
                </button>
              ))}
            </div>
          </article>
        </section>

        {selectedSummary && (
          <section className="mt-6 rounded-2xl border border-cyan-300/20 bg-cyan-300/[0.055] p-5 sm:p-6">
            <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <div className="flex flex-wrap items-center gap-3">
                  <p className="font-mono text-lg font-medium text-white">{selectedSummary.ip}</p>
                  <span className={'rounded-full border px-2.5 py-1 text-xs font-medium ' + riskClass(selectedSummary.risk)}>
                    {selectedSummary.risk} ryzyko
                  </span>
                </div>
                <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
                  Pierwszy wpis: {selectedSummary.firstSeen}. Ostatni wpis: {selectedSummary.lastSeen}. Cele: {selectedSummary.users.join(', ') || 'brak rozpoznanego konta'}.
                </p>
              </div>
              <div className="flex flex-wrap gap-3">
                <button
                  type="button"
                  onClick={() => addToBlocklist(selectedSummary)}
                  disabled={blocklist.some((entry) => entry.ip === selectedSummary.ip)}
                  className="self-start rounded-xl border border-rose-300/20 bg-rose-300/8 px-3 py-2 text-xs font-medium text-rose-100 transition hover:bg-rose-300/15 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {blocklist.some((entry) => entry.ip === selectedSummary.ip)
                    ? 'Już na liście blokad'
                    : 'Dodaj do listy blokad'}
                </button>
                <button type="button" onClick={() => setSelectedIp(null)} className="self-start text-sm text-cyan-100 underline decoration-cyan-300/40 underline-offset-4 hover:text-white">
                  Zamknij szczegóły
                </button>
              </div>
            </div>
            <div className="mt-5 grid gap-3 sm:grid-cols-4">
              <div className="rounded-xl bg-black/15 p-3"><p className="text-xs text-slate-500">Wszystkie zdarzenia</p><p className="mt-1 text-xl font-semibold text-white">{selectedSummary.total}</p></div>
              <div className="rounded-xl bg-black/15 p-3"><p className="text-xs text-slate-500">Odrzucone</p><p className="mt-1 text-xl font-semibold text-rose-200">{selectedSummary.failed}</p></div>
              <div className="rounded-xl bg-black/15 p-3"><p className="text-xs text-slate-500">Próby na root</p><p className="mt-1 text-xl font-semibold text-amber-100">{selectedSummary.rootAttempts}</p></div>
              <div className="rounded-xl bg-black/15 p-3"><p className="text-xs text-slate-500">Udane</p><p className="mt-1 text-xl font-semibold text-emerald-200">{selectedSummary.accepted}</p></div>
            </div>
            <p className="mt-4 text-xs text-slate-500">
              Ostatnie zdarzenia z tego adresu: {selectedEvents.slice(-3).map((event) => event.timestamp).join(' · ')}
            </p>
          </section>
        )}

        <section className="mt-6 rounded-2xl border border-white/8 bg-white/[0.035] p-5 sm:p-6">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <p className="text-sm font-semibold text-white">Zdarzenia SSH</p>
              <p className="mt-1 text-sm text-slate-500">Szukaj po adresie IP, użytkowniku, metodzie lub treści wpisu.</p>
            </div>
            <button type="button" onClick={exportCsv} className="rounded-xl bg-cyan-200 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-white">
              Eksportuj CSV
            </button>
          </div>

          <div className="mt-5 grid gap-3 md:grid-cols-[minmax(0,1fr)_180px_180px]">
            <label className="relative block">
              <span className="sr-only">Szukaj zdarzeń</span>
              <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">⌕</span>
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Szukaj IP, użytkownika lub wpisu…"
                className="w-full rounded-xl border border-white/10 bg-black/15 py-2.5 pl-9 pr-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-cyan-300/50"
              />
            </label>
            <select
              value={eventFilter}
              onChange={(event) => setEventFilter(event.target.value as EventFilter)}
              className="rounded-xl border border-white/10 bg-[#0a1420] px-3 py-2.5 text-sm text-slate-200 outline-none focus:border-cyan-300/50"
            >
              <option value="all">Wszystkie wyniki</option>
              <option value="failed">Odrzucono</option>
              <option value="accepted">Zalogowano</option>
              <option value="invalid_user">Nieznany użytkownik</option>
              <option value="connection_closed">Przerwane połączenie</option>
              <option value="unknown">Nierozpoznane</option>
            </select>
            <select
              value={riskFilter}
              onChange={(event) => setRiskFilter(event.target.value as RiskFilter)}
              className="rounded-xl border border-white/10 bg-[#0a1420] px-3 py-2.5 text-sm text-slate-200 outline-none focus:border-cyan-300/50"
            >
              <option value="all">Każdy poziom ryzyka</option>
              <option value="high">Tylko wysokie</option>
              <option value="medium">Średnie i wysokie</option>
            </select>
          </div>

          <div className="mt-5 overflow-x-auto">
            <div className="min-w-[820px]">
              <div className="grid grid-cols-[150px_1.2fr_1fr_150px_110px] gap-4 border-b border-white/8 px-3 pb-3 text-[11px] font-medium uppercase tracking-[0.12em] text-slate-500">
                <span>Czas</span><span>Adres / użytkownik</span><span>Typ</span><span>Metoda</span><span>Ryzyko</span>
              </div>
              <div className="divide-y divide-white/[0.06]">
                {filteredEvents.map((event) => {
                  const meta = EVENT_META[event.eventType];
                  const risk = event.sourceIp ? riskByIp.get(event.sourceIp) ?? 'Niskie' : 'Niskie';
                  return (
                    <button
                      type="button"
                      key={event.id}
                      onClick={() => event.sourceIp && setSelectedIp(event.sourceIp)}
                      className="grid w-full grid-cols-[150px_1.2fr_1fr_150px_110px] gap-4 px-3 py-3.5 text-left transition hover:bg-white/[0.035] focus:outline-none focus-visible:bg-white/[0.06]"
                      title={event.rawLine}
                    >
                      <span className="font-mono text-xs text-slate-400">{event.timestamp}</span>
                      <span className="min-w-0">
                        <span className="block truncate font-mono text-sm text-slate-100">{event.sourceIp ?? '—'}</span>
                        <span className="mt-0.5 block truncate text-xs text-slate-500">
                          {event.username ? 'użytkownik: ' + event.username : event.hostname}
                        </span>
                      </span>
                      <span className="flex items-center gap-2">
                        <span className={'h-1.5 w-1.5 rounded-full ' + meta.dot} />
                        <span className={'w-fit rounded-full border px-2 py-1 text-[11px] ' + meta.badge}>
                          {meta.label}
                        </span>
                      </span>
                      <span className="text-sm text-slate-400">{event.authMethod ?? (event.preauth ? 'preauth' : '—')}</span>
                      <span className={'w-fit self-center rounded-full border px-2.5 py-1 text-[11px] ' + riskClass(risk)}>
                        {risk}
                      </span>
                    </button>
                  );
                })}
                {!filteredEvents.length && (
                  <p className="px-3 py-10 text-center text-sm text-slate-500">
                    Brak zdarzeń pasujących do ustawionych filtrów.
                  </p>
                )}
              </div>
            </div>
          </div>
        </section>

        <footer className="mt-6 rounded-2xl border border-white/8 bg-white/[0.025] px-5 py-4 text-xs leading-5 text-slate-500">
          Ocena ryzyka jest wskazówką: wysoki poziom oznacza m.in. co najmniej 10 błędów logowania, serię prób na konto <code className="text-slate-400">root</code> lub szerokie zgadywanie kont. Zawsze sprawdź zdarzenia przed zablokowaniem adresu.
        </footer>
      </div>
    </main>
  );
}
