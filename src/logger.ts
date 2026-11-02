export type LogLevel = "info" | "warn" | "error" | "debug";
export type Decision = "allow" | "deny" | "error" | null;

export interface LogEvent {
  ts?: string;
  level: LogLevel;
  reqId: string;
  role: string | null;
  method: string | null;
  tool: string | null;
  decision: Decision;
  status: number;
  durationMs: number;
}

export type LogSink = (line: string) => void;

const defaultSink: LogSink = (line: string) => {
  process.stderr.write(line + "\n");
};

export class Logger {
  private sink: LogSink;

  constructor(sink: LogSink = defaultSink) {
    this.sink = sink;
  }

  log(event: LogEvent): void {
    const record = {
      ts: event.ts || new Date().toISOString(),
      level: event.level,
      reqId: event.reqId,
      role: event.role,
      method: event.method,
      tool: event.tool,
      decision: event.decision,
      status: event.status,
      durationMs: event.durationMs
    };
    this.sink(JSON.stringify(record));
  }

  info(event: Omit<LogEvent, "level">): void {
    this.log({ ...event, level: "info" });
  }

  warn(event: Omit<LogEvent, "level">): void {
    this.log({ ...event, level: "warn" });
  }

  error(event: Omit<LogEvent, "level">): void {
    this.log({ ...event, level: "error" });
  }
}

export const logger = new Logger();
