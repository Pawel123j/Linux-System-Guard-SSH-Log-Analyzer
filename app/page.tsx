'use client';

import {
  ChangeEvent,
  DragEvent,
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

function calculateRisk(summary: Omit<IpSummary, 'risk' | 'score'>) {
  const broadTargeting = summary.failed >= 5 && summary.users.length >= 3;
  const score =
    (summary.failed >= 10 ? 5 : summary.failed >= 5 ? 3 : summary.failed >= 3 ? 1 : 0) +
    (summary.invalidUsers >= 4 ? 3 : summary.invalidUsers >= 2 ? 1 : 0) +
    (summary.rootAttempts >= 3 ? 2 : 0) +
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

function makeIpSummaries(events: AuthEvent[]): IpSummary[] {
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
      return { ...withUsers, ...calculateRisk(withUsers) };
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
  const [query, setQuery] = useState('');
  const [eventFilter, setEventFilter] = useState<EventFilter>('all');
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [selectedIp, setSelectedIp] = useState<string | null>(null);

  const ipSummaries = useMemo(() => makeIpSummaries(events), [events]);
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
    return { failed, accepted, invalidUsers, suspicious };
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

  function showNotice(message: string, timeout = 4000) {
    setNotice(message);
    window.setTimeout(() => setNotice(''), timeout);
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
              <button type="button" onClick={() => setSelectedIp(null)} className="self-start text-sm text-cyan-100 underline decoration-cyan-300/40 underline-offset-4 hover:text-white">
                Zamknij szczegóły
              </button>
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
