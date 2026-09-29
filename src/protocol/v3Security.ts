/** Supported SNMPv3 USM authentication protocols. */
export type UsmAuthProtocol = "sha1";

/** Supported SNMPv3 USM privacy protocols. */
export type UsmPrivacyProtocol = "des";

/** SNMPv3 USM options for messages without authentication or privacy. */
export interface NoAuthNoPrivOptions {
  /** USM security level; username is still required for user lookup. */
  securityLevel: "noAuthNoPriv";
  /** USM security name used by the authoritative SNMP engine. */
  username: string;
}

/** SNMPv3 USM options for authenticated messages without privacy. */
export interface AuthNoPrivOptions {
  /** USM security level requiring message authentication. */
  securityLevel: "authNoPriv";
  /** USM security name used by the authoritative SNMP engine. */
  username: string;
  /** Passphrase from which the localized SHA-1 USM key is derived. */
  authPassword: string;
  /** Authentication algorithm; SHA-1 is the supported interoperable option. */
  authProtocol?: UsmAuthProtocol;
}

/** SNMPv3 USM options for authenticated and DES-encrypted messages. */
export interface AuthPrivOptions {
  /** USM security level requiring both authentication and privacy. */
  securityLevel: "authPriv";
  /** USM security name used by the authoritative SNMP engine. */
  username: string;
  /** Passphrase from which the localized SHA-1 USM key is derived. */
  authPassword: string;
  /** Passphrase from which the localized DES privacy key is derived. */
  privacyPassword: string;
  /** Authentication algorithm; SHA-1 is the supported interoperable option. */
  authProtocol?: UsmAuthProtocol;
  /** Privacy algorithm; legacy USM DES privacy as requested. */
  privacyProtocol?: UsmPrivacyProtocol;
}

/** Discriminated configuration for the three SNMPv3 USM security levels. */
export type SnmpV3SecurityOptions =
  | NoAuthNoPrivOptions
  | AuthNoPrivOptions
  | AuthPrivOptions;
