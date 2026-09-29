import { createSocket, type Socket } from "node:dgram";
import { isIP } from "node:net";
import { SnmpError, SnmpTimeoutError } from "../types.ts";

/** Configuration required by the UDP transport base class. */
export interface UdpTransportOptions {
  /** Agent host name or IP address. */
  host: string;
  /** Agent UDP port. */
  port: number;
  /** Timeout for each send attempt. */
  timeoutMs: number;
  /** Retries after the initial send attempt. */
  retries: number;
}

/** Predicate used to associate an incoming datagram with its request. */
export type ResponseMatcher = (packet: Uint8Array) => boolean;

/**
 * Abstract UDP request/response transport shared by SNMP protocol versions.
 * It owns one socket, correlates requests via protocol-level matchers, and
 * applies timeout/retry policy without embedding SNMP message details.
 */
export abstract class UdpTransport {
  private socket?: Socket;
  private bindPromise?: Promise<void>;
  private readonly pending = new Set<PendingRequest>();
  private closed = false;

  /** Create a transport for one target agent. */
  protected constructor(private readonly options: UdpTransportOptions) {}

  /** Provide the correct UDP socket family for the configured endpoint. */
  protected abstract createSocket(): Socket;

  /** Send a packet and resolve with the first matching response datagram. */
  async exchange(packet: Uint8Array, matcher: ResponseMatcher): Promise<Uint8Array> {
    if (this.closed) throw new SnmpError("UDP transport is closed", "SNMP_TRANSPORT_CLOSED");
    await this.ensureBound();
    if (this.closed) throw new SnmpError("UDP transport is closed", "SNMP_TRANSPORT_CLOSED");

    return new Promise<Uint8Array>((resolve, reject) => {
      const pending: PendingRequest = {
        packet,
        matcher,
        attempts: 0,
        resolve,
        reject,
        timeout: undefined,
      };
      this.pending.add(pending);
      this.sendAttempt(pending);
    });
  }

  /** Close the socket and reject any outstanding requests. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const error = new SnmpError("UDP transport closed before response arrived", "SNMP_TRANSPORT_CLOSED");
    for (const request of this.pending) this.rejectRequest(request, error);
    await this.bindPromise?.catch(() => undefined);
    const socket = this.socket;
    if (!socket) return;

    await new Promise<void>((resolve) => {
      try {
        socket.close(() => resolve());
      } catch {
        resolve();
      }
    });
  }

  /** Bind the socket once before its first request is sent. */
  private async ensureBound(): Promise<void> {
    if (this.bindPromise) return this.bindPromise;
    const socket = this.createSocket();
    this.socket = socket;
    socket.on("message", (message, remote) => this.receive(message, remote.port));
    socket.on("error", (error) => this.failAll(error));
    this.bindPromise = new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => {
        socket.off("listening", onListening);
        reject(error);
      };
      const onListening = () => {
        socket.off("error", onError);
        resolve();
      };
      socket.once("error", onError);
      socket.once("listening", onListening);
      socket.bind(0);
    });
    return this.bindPromise;
  }

  /** Retry a pending request and arm the next per-attempt timeout. */
  private sendAttempt(request: PendingRequest): void {
    const socket = this.socket;
    if (!socket) {
      this.rejectRequest(request, new SnmpError("UDP socket is unavailable", "SNMP_TRANSPORT_ERROR"));
      return;
    }

    request.attempts += 1;
    socket.send(request.packet, this.options.port, this.options.host, (error) => {
      if (error) this.rejectRequest(request, new SnmpError(error.message, "SNMP_TRANSPORT_ERROR", { cause: error }));
    });
    request.timeout = setTimeout(() => {
      if (request.attempts <= this.options.retries) {
        this.sendAttempt(request);
      } else {
        this.rejectRequest(
          request,
          new SnmpTimeoutError(`No SNMP response from ${this.options.host}:${this.options.port} after ${request.attempts} attempts`),
        );
      }
    }, this.options.timeoutMs);
  }

  /** Match incoming datagrams to requests and deliver the first valid response. */
  private receive(message: Uint8Array, remotePort: number): void {
    if (remotePort !== this.options.port) return;
    for (const request of this.pending) {
      let matches = false;
      try {
        matches = request.matcher(message);
      } catch {
        matches = false;
      }
      if (matches) {
        this.resolveRequest(request, message.slice());
        return;
      }
    }
  }

  /** Reject all requests after a fatal socket error. */
  private failAll(error: Error): void {
    for (const request of this.pending) {
      this.rejectRequest(request, new SnmpError(error.message, "SNMP_TRANSPORT_ERROR", { cause: error }));
    }
  }

  /** Resolve and remove a request while clearing its active timer. */
  private resolveRequest(request: PendingRequest, packet: Uint8Array): void {
    this.removeRequest(request);
    request.resolve(packet);
  }

  /** Reject and remove a request while clearing its active timer. */
  private rejectRequest(request: PendingRequest, error: Error): void {
    if (!this.pending.has(request)) return;
    this.removeRequest(request);
    request.reject(error);
  }

  /** Remove request bookkeeping and cancel the current timeout. */
  private removeRequest(request: PendingRequest): void {
    this.pending.delete(request);
    if (request.timeout) clearTimeout(request.timeout);
  }
}

/** Default transport implementation selecting UDP4 or UDP6 from an IP literal. */
export class DefaultUdpTransport extends UdpTransport {
  /** Create the base class implementation for the supplied agent options. */
  constructor(options: UdpTransportOptions) {
    super(options);
    this.host = options.host;
  }

  private readonly host: string;

  /** Pick UDP6 for IPv6 literals and UDP4 for IPv4 literals or host names. */
  protected createSocket(): Socket {
    return createSocket(isIP(this.host) === 6 ? "udp6" : "udp4");
  }
}

/** Internal state for an outstanding UDP exchange. */
interface PendingRequest {
  /** Packet retransmitted for each configured attempt. */
  packet: Uint8Array;
  /** Protocol-specific response correlation predicate. */
  matcher: ResponseMatcher;
  /** Current send attempt, including the initial transmission. */
  attempts: number;
  /** Promise resolve callback. */
  resolve: (packet: Uint8Array) => void;
  /** Promise reject callback. */
  reject: (error: Error) => void;
  /** Active timeout for the current attempt. */
  timeout?: ReturnType<typeof setTimeout>;
}
