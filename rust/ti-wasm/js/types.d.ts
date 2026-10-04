// The JSON the exports return, as tsl-view.json and certificates.json describe it.
// Schema 1: fields are only added within it.

/** Lower-case SHA-256 hex of the DER; the key of `TslView.certificates`. */
export type Fingerprint = string;

export interface Version {
  ti_wasm: string;
  schema: 1;
}

export interface TrustUrls {
  environment: Environment;
  tsl_url: string;
  roots_url: string;
}

export type Environment = 'prod' | 'ref' | 'test' | 'dev';

export interface Finding {
  /** e.g. `xml_signature_error`, `validity_warning_1`, `no_ocsp_check` */
  code: string;
  /** Tab_PKI_274 number */
  code_number: number | null;
  /** Rule of spec/tsl-xmldsig, e.g. `TSLSIG-018` */
  rule: string;
  /** For humans; not stable */
  detail: string;
}

export interface TslView {
  schema: 1;
  environment: Environment;
  tier: 'prod' | 'nonprod';
  result: 'valid' | 'invalid';
  error: Finding | null;
  signature: SignatureView | null;
  list: ListView | null;
  roots: RootsView | null;
  counts: Counts | null;
  providers: ProviderView[];
  skipped: { provider: string; name: string; reason: string }[];
  certificates: Record<Fingerprint, CertificateInfo>;
}

export interface SignatureView {
  signer: Fingerprint;
  tsl_signer_ca: Fingerprint;
  signing_time: string;
  warnings: Finding[];
}

export interface ListView {
  id: string;
  sequence_number: number;
  issued_at: string;
  next_update: string | null;
  /** Past next_update, within the grace period */
  overdue: boolean;
  scheme: SchemeView;
}

export interface SchemeView {
  version_identifier: number | null;
  tsl_type: string;
  scheme_name: string;
  operator_name: string;
  postal_addresses: {
    street: string;
    postal_code: string;
    locality: string;
    state: string;
    country: string;
  }[];
  electronic_addresses: string[];
  primary_location: string | null;
  backup_location: string | null;
  pointers: { location: string; additional_information: string[] }[];
}

export interface RootsView {
  source: 'supplied' | 'embedded';
  /** Why the supplied roots.json was not used */
  warning: string | null;
  trusted: {
    fingerprint: Fingerprint;
    common_name: string;
    not_after: string;
    validity: Validity;
    cas: Fingerprint[];
  }[];
}

export interface Counts {
  providers: number;
  services: number;
  cas_listed: number;
  cas_kept: number;
  cas_rejected: number;
  ocsp: number;
  skipped: number;
}

export interface ProviderView {
  name: string;
  services: ServiceView[];
}

export interface ServiceView {
  name: string;
  service_type: string;
  kind: 'ca' | 'ocsp' | 'tsl_cert_change' | 'other';
  status: string;
  in_accord: boolean;
  status_starting_time: string | null;
  supply_points: string[];
  type_oids: { oid: string; reference: string | null; name: string | null }[];
  certificate: Fingerprint | null;
  chain: ChainView | null;
}

export interface ChainView {
  trusted: boolean;
  /** The service certificate first, up to the root as far as built */
  path: Fingerprint[];
  rejection: 'not_ca' | 'self_signed' | 'unknown_issuer' | 'bad_signature' | 'other' | null;
}

export type Validity = 'valid' | 'expired' | 'not_yet_valid';

export interface OidInfo {
  oid: string;
  name: string | null;
}

export interface CertificateInfo {
  subject: string;
  subject_alt_names: string[];
  issuer: string;
  serial: string;
  not_before: string;
  not_after: string;
  validity: Validity;
  key: { algorithm: string; status: string };
  signature_algorithm: string;
  /** gemSpec_PKI type, e.g. C.HCI.AUT */
  certificate_type: string | null;
  profile: { name: string; reason: string; detail: string } | null;
  admission: {
    profession_items: string[];
    profession_oids: OidInfo[];
    registration_number: string | null;
  } | null;
  policies: OidInfo[];
  key_usage: string[];
  extended_key_usage: string[];
  ca: boolean;
  path_len: number | null;
  ocsp_urls: string[];
  critical_extensions: string[];
  subject_key_id: string | null;
  authority_key_id: string | null;
  /** Upper-case hex, colon-separated */
  sha256: string;
  pem: string;
}

export interface Certificates {
  schema: 1;
  certificates: CertificateInfo[];
}
