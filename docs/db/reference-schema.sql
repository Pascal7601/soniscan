-- =====================================================================
-- Security Posture Scanner: initial schema
-- Target: PostgreSQL 15+ (uses security_invoker views)
-- Design principles:
--   1. Tenant isolation enforced in the database (row-level security), not only in app code.
--   2. Active scans are impossible against unverified domains (trigger guard).
--   3. Findings have a lifecycle across scans; evidence is kept per scan.
--   4. Check text and scoring constants are versioned so old reports stay reproducible.
--   5. Never store plaintext passwords or raw leaked credentials.
-- =====================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS citext;

-- ---------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------

CREATE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

-- The app (and each scanner job) sets this per connection/transaction:
--   SET LOCAL app.current_tenant = '<tenant uuid>';
-- If unset, it returns NULL and RLS policies match no rows (fail closed).
CREATE FUNCTION current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('app.current_tenant', true), '')::uuid
$$;

-- ---------------------------------------------------------------------
-- Plans, tenants, users
-- ---------------------------------------------------------------------

CREATE TABLE plans (
  key                   text PRIMARY KEY,
  display_name          text    NOT NULL,
  max_domains           integer NOT NULL CHECK (max_domains >= 0),
  max_scans_per_month   integer NOT NULL CHECK (max_scans_per_month >= 0),
  active_scans_allowed  boolean NOT NULL DEFAULT false,
  continuous_monitoring boolean NOT NULL DEFAULT false
);

INSERT INTO plans (key, display_name, max_domains, max_scans_per_month, active_scans_allowed, continuous_monitoring) VALUES
  ('free',     'Free',     1,   3, false, false),
  ('starter',  'Starter',  3,  30, true,  true),
  ('business', 'Business', 10, 150, true, true);

CREATE TABLE tenants (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text NOT NULL,
  plan       text NOT NULL DEFAULT 'free' REFERENCES plans(key),
  status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         citext NOT NULL UNIQUE,
  display_name  text,
  auth_subject  text UNIQUE,            -- subject id from the identity provider; no passwords stored here
  mfa_enabled   boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz,
  deleted_at    timestamptz
);

CREATE TABLE memberships (
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
  role       text NOT NULL CHECK (role IN ('owner', 'admin', 'viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE subscriptions (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id                uuid NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
  plan                     text NOT NULL REFERENCES plans(key),
  status                   text NOT NULL CHECK (status IN ('trialing', 'active', 'past_due', 'cancelled')),
  provider                 text NOT NULL,
  provider_customer_id     text NOT NULL,
  provider_subscription_id text NOT NULL,
  current_period_end       timestamptz,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_subscription_id)
);

-- ---------------------------------------------------------------------
-- Domains and ownership verification
-- ---------------------------------------------------------------------

CREATE TABLE domains (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  fqdn           text NOT NULL
                 CHECK (fqdn = lower(fqdn)
                        AND fqdn ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
  status         text NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'verified', 'expired', 'suspended')),
  verified_at    timestamptz,
  verified_method text CHECK (verified_method IN ('dns_txt', 'http_file')),
  reverify_due   timestamptz,           -- verification is re-checked (e.g. every 90 days)
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, fqdn),
  UNIQUE (id, tenant_id),               -- target for composite foreign keys below
  CHECK (status <> 'verified'
         OR (verified_at IS NOT NULL AND verified_method IS NOT NULL AND reverify_due IS NOT NULL))
);

-- Only one tenant can hold a verified claim on a given domain at a time.
CREATE UNIQUE INDEX domains_single_verified_owner ON domains (fqdn) WHERE status = 'verified';
CREATE INDEX domains_tenant_idx ON domains (tenant_id);

CREATE TABLE domain_verifications (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL,
  domain_id  uuid NOT NULL,
  method     text  NOT NULL CHECK (method IN ('dns_txt', 'http_file')),
  token_hash bytea NOT NULL,            -- SHA-256 of the token; the token is shown to the user once
  expires_at timestamptz NOT NULL,
  checked_at timestamptz,
  result     text NOT NULL DEFAULT 'pending' CHECK (result IN ('pending', 'verified', 'failed', 'expired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (domain_id, tenant_id) REFERENCES domains (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX domain_verifications_domain_idx ON domain_verifications (domain_id);

-- ---------------------------------------------------------------------
-- Assets discovered for a domain
-- ---------------------------------------------------------------------

CREATE TABLE assets (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL,
  domain_id      uuid NOT NULL,
  type           text NOT NULL CHECK (type IN ('apex', 'subdomain', 'ip', 'mail_server', 'service')),
  value          text NOT NULL,         -- e.g. 'mail.example.com', '203.0.113.5', '203.0.113.5:3389/tcp'
  attributes     jsonb NOT NULL DEFAULT '{}'::jsonb,
  is_third_party boolean NOT NULL DEFAULT false,  -- SaaS, CDN, shared hosting: never actively scanned
  in_scope       boolean NOT NULL DEFAULT true,
  first_seen_at  timestamptz NOT NULL DEFAULT now(),
  last_seen_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (domain_id, type, value),
  UNIQUE (id, tenant_id),
  FOREIGN KEY (domain_id, tenant_id) REFERENCES domains (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX assets_domain_type_idx ON assets (domain_id, type);

-- ---------------------------------------------------------------------
-- Check library and scoring constants (both versioned)
-- ---------------------------------------------------------------------

CREATE TABLE check_definitions (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  check_key             text    NOT NULL,        -- stable id, e.g. EMAIL_DMARC_MONITOR_ONLY
  version               integer NOT NULL,
  category              text NOT NULL CHECK (category IN
                          ('email', 'tls', 'web', 'subdomain', 'exposed_service', 'software', 'credentials')),
  requires_verification boolean NOT NULL,        -- true for active scans and breach lookups
  title                 text NOT NULL,
  severity_base         text NOT NULL CHECK (severity_base IN ('critical', 'high', 'medium', 'low', 'info')),
  exploitability_base   numeric(3,2) NOT NULL CHECK (exploitability_base BETWEEN 0 AND 1),
  plain_explanation     text NOT NULL,           -- what is wrong, in everyday language
  why_it_matters        text NOT NULL,           -- business consequence
  fix_steps             jsonb NOT NULL,          -- ordered JSON array of strings
  effort                text NOT NULL CHECK (effort IN ('minutes', 'hours', 'days')),
  owner_hint            text,                    -- e.g. 'whoever manages your domain'
  reference_links       jsonb NOT NULL DEFAULT '[]'::jsonb,
  is_active             boolean NOT NULL DEFAULT true,
  created_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (check_key, version)
);

CREATE TABLE scoring_models (
  version    integer PRIMARY KEY,
  params     jsonb NOT NULL,
  notes      text,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO scoring_models (version, params, notes) VALUES (
  1,
  '{"severity_weights": {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0},
    "decay_k": 40,
    "repeat_factor": 0.5,
    "grade_caps": {"critical": 69, "high": 79},
    "grade_bands": {"A": 90, "B": 80, "C": 70, "D": 60}}'::jsonb,
  'Initial constants; calibrate against pilot scans.'
);

INSERT INTO check_definitions
  (check_key, version, category, requires_verification, title, severity_base, exploitability_base,
   plain_explanation, why_it_matters, fix_steps, effort, owner_hint)
VALUES
  ('EMAIL_DMARC_MONITOR_ONLY', 1, 'email', false,
   'Fake emails can be sent in your company''s name',
   'medium', 0.80,
   'Your domain has a DMARC rule set to monitor only, so email providers still deliver messages that fake your address.',
   'Criminals use this to send fake invoices and payment requests to your customers and staff in your name.',
   '["Log in to wherever your domain''s DNS is managed.",
     "Change the DMARC policy from none to quarantine.",
     "Review the DMARC reports for two weeks, then move the policy to reject."]'::jsonb,
   'minutes', 'Whoever manages your domain'),
  ('SVC_RDP_EXPOSED', 1, 'exposed_service', true,
   'Remote desktop is open to the whole internet',
   'critical', 1.00,
   'A Windows remote-access service (RDP) answers connections from anywhere on the internet.',
   'Attackers constantly scan for this and use stolen or guessed passwords to take control of the computer, a common start of ransomware attacks.',
   '["Block port 3389 from the internet at your firewall or router.",
     "Allow remote access only through a VPN or a secure gateway.",
     "Turn on multi-factor authentication for remote logins."]'::jsonb,
   'hours', 'Your IT provider or firewall administrator');

-- ---------------------------------------------------------------------
-- Scans
-- ---------------------------------------------------------------------

CREATE TABLE scans (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL,
  domain_id             uuid NOT NULL,
  trigger_type          text NOT NULL CHECK (trigger_type IN ('manual', 'scheduled')),
  mode                  text NOT NULL CHECK (mode IN ('passive', 'active')),
  status                text NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled', 'refused')),
  requested_by          uuid REFERENCES users(id) ON DELETE SET NULL,
  scanner_version       text,
  check_library_note    text,
  queued_at             timestamptz NOT NULL DEFAULT now(),
  started_at            timestamptz,
  finished_at           timestamptz,
  error                 text,
  raw_output_key        text,            -- object-storage key for raw tool output
  raw_expires_at        timestamptz,     -- short retention for raw output
  UNIQUE (id, tenant_id),
  FOREIGN KEY (domain_id, tenant_id) REFERENCES domains (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX scans_domain_queued_idx ON scans (domain_id, queued_at DESC);
CREATE INDEX scans_pending_idx ON scans (status) WHERE status IN ('queued', 'running');

-- Defence in depth: an active scan can only be queued or run while the domain is verified
-- and its verification has not lapsed. The API checks this too; the database enforces it.
CREATE FUNCTION enforce_active_scan_requires_verification() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  d_status text;
  d_due    timestamptz;
BEGIN
  IF NEW.mode = 'active' AND NEW.status IN ('queued', 'running') THEN
    SELECT status, reverify_due INTO d_status, d_due FROM domains WHERE id = NEW.domain_id;
    IF d_status IS DISTINCT FROM 'verified' OR d_due IS NULL OR d_due <= now() THEN
      RAISE EXCEPTION 'active scan refused: domain % is not currently verified', NEW.domain_id
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER scans_active_guard
  BEFORE INSERT OR UPDATE OF mode, status ON scans
  FOR EACH ROW EXECUTE FUNCTION enforce_active_scan_requires_verification();

-- ---------------------------------------------------------------------
-- Findings (lifecycle) and observations (evidence per scan)
-- ---------------------------------------------------------------------

CREATE TABLE findings (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL,
  domain_id           uuid NOT NULL,
  asset_id            uuid,
  check_definition_id uuid NOT NULL REFERENCES check_definitions(id),
  fingerprint         text NOT NULL,     -- stable hash of check_key + asset, identical across scans
  status              text NOT NULL DEFAULT 'open'
                      CHECK (status IN ('open', 'fixed', 'accepted_risk', 'false_positive')),
  severity            text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  exploitability      numeric(3,2) NOT NULL CHECK (exploitability BETWEEN 0 AND 1),
  exposure            numeric(3,2) NOT NULL CHECK (exposure BETWEEN 0 AND 1),
  score               numeric(4,2) NOT NULL CHECK (score BETWEEN 0 AND 10),   -- latest observation
  first_seen_scan_id  uuid NOT NULL,
  last_seen_scan_id   uuid NOT NULL,
  first_seen_at       timestamptz NOT NULL DEFAULT now(),
  last_seen_at        timestamptz NOT NULL DEFAULT now(),
  fixed_at            timestamptz,
  reopened_count      integer NOT NULL DEFAULT 0,
  accepted_by         uuid REFERENCES users(id) ON DELETE SET NULL,
  accepted_reason     text,
  accepted_until      timestamptz,
  UNIQUE (domain_id, fingerprint),
  UNIQUE (id, tenant_id),
  CHECK (status <> 'accepted_risk' OR accepted_reason IS NOT NULL),
  FOREIGN KEY (domain_id, tenant_id) REFERENCES domains (id, tenant_id) ON DELETE CASCADE,
  FOREIGN KEY (asset_id, tenant_id) REFERENCES assets (id, tenant_id),
  FOREIGN KEY (first_seen_scan_id, tenant_id) REFERENCES scans (id, tenant_id),
  FOREIGN KEY (last_seen_scan_id, tenant_id) REFERENCES scans (id, tenant_id)
);
CREATE INDEX findings_open_ranked_idx ON findings (tenant_id, status, score DESC);
CREATE INDEX findings_domain_status_idx ON findings (domain_id, status);

CREATE TABLE finding_observations (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL,
  finding_id            uuid NOT NULL,
  scan_id               uuid NOT NULL,
  severity              text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  exploitability        numeric(3,2) NOT NULL CHECK (exploitability BETWEEN 0 AND 1),
  exposure              numeric(3,2) NOT NULL CHECK (exposure BETWEEN 0 AND 1),
  score                 numeric(4,2) NOT NULL CHECK (score BETWEEN 0 AND 10),
  scoring_model_version integer NOT NULL REFERENCES scoring_models(version),
  evidence              jsonb NOT NULL DEFAULT '{}'::jsonb,
  observed_at           timestamptz NOT NULL DEFAULT now(),
  UNIQUE (finding_id, scan_id),
  FOREIGN KEY (finding_id, tenant_id) REFERENCES findings (id, tenant_id) ON DELETE CASCADE,
  FOREIGN KEY (scan_id, tenant_id) REFERENCES scans (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX finding_observations_scan_idx ON finding_observations (scan_id);

-- Breach exposure metadata only. No credentials and no per-account detail are stored;
-- account lists are fetched live from the provider when an authorised user views them.
CREATE TABLE breach_exposures (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL,
  domain_id         uuid NOT NULL,
  breach_name       text NOT NULL,
  breach_date       date,
  data_classes      text[] NOT NULL DEFAULT '{}',
  affected_accounts integer NOT NULL CHECK (affected_accounts >= 0),
  source            text NOT NULL,
  first_seen_at     timestamptz NOT NULL DEFAULT now(),
  last_seen_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (domain_id, source, breach_name),
  FOREIGN KEY (domain_id, tenant_id) REFERENCES domains (id, tenant_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------
-- Reports
-- ---------------------------------------------------------------------

CREATE TABLE reports (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL,
  domain_id             uuid NOT NULL,
  scan_id               uuid NOT NULL UNIQUE,   -- one report per scan
  score                 smallint NOT NULL CHECK (score BETWEEN 0 AND 100),
  grade                 char(1)  NOT NULL CHECK (grade IN ('A', 'B', 'C', 'D', 'F')),
  total_risk            numeric(6,2) NOT NULL CHECK (total_risk >= 0),
  scoring_model_version integer NOT NULL REFERENCES scoring_models(version),
  summary               jsonb NOT NULL DEFAULT '{}'::jsonb,   -- counts by tier and category, for trend charts
  storage_key           text,                   -- PDF in object storage
  sha256                bytea,
  created_at            timestamptz NOT NULL DEFAULT now(),
  expires_at            timestamptz,
  FOREIGN KEY (domain_id, tenant_id) REFERENCES domains (id, tenant_id) ON DELETE CASCADE,
  FOREIGN KEY (scan_id, tenant_id) REFERENCES scans (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX reports_domain_created_idx ON reports (domain_id, created_at DESC);

-- ---------------------------------------------------------------------
-- Free teaser scans: passive only, no tenant, short retention
-- ---------------------------------------------------------------------

CREATE TABLE teaser_scans (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  fqdn                text NOT NULL CHECK (fqdn = lower(fqdn)),
  lead_email          citext,
  marketing_consent   boolean NOT NULL DEFAULT false,
  requester_ip_hash   bytea NOT NULL,           -- salted hash, used only for rate limiting
  status              text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
  summary             jsonb NOT NULL DEFAULT '{}'::jsonb,  -- grade plus a few passive findings
  converted_tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  finished_at         timestamptz,
  expires_at          timestamptz NOT NULL DEFAULT now() + interval '30 days'
);
CREATE INDEX teaser_scans_expiry_idx ON teaser_scans (expires_at);
CREATE INDEX teaser_scans_ratelimit_idx ON teaser_scans (requester_ip_hash, created_at);

-- ---------------------------------------------------------------------
-- Audit log: append-only
-- ---------------------------------------------------------------------

CREATE TABLE audit_log (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  tenant_id   uuid,                              -- deliberately no FK: history outlives tenants
  actor_type  text NOT NULL CHECK (actor_type IN ('user', 'system', 'scanner')),
  actor_id    uuid,
  action      text NOT NULL,                     -- e.g. domain.verified, scan.requested, scan.refused
  target_type text,
  target_id   uuid,
  ip          inet,
  user_agent  text,
  metadata    jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_tenant_time_idx ON audit_log (tenant_id, occurred_at DESC);

CREATE FUNCTION audit_log_reject_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END $$;

CREATE TRIGGER audit_log_no_update_delete
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_reject_change();

CREATE TRIGGER audit_log_no_truncate
  BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_change();

-- ---------------------------------------------------------------------
-- updated_at triggers
-- ---------------------------------------------------------------------

CREATE TRIGGER tenants_updated       BEFORE UPDATE ON tenants       FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER users_updated         BEFORE UPDATE ON users         FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER domains_updated       BEFORE UPDATE ON domains       FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER subscriptions_updated BEFORE UPDATE ON subscriptions FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- Row-level security: every tenant-owned table, fail closed
-- ---------------------------------------------------------------------

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'memberships', 'subscriptions', 'domains', 'domain_verifications', 'assets',
    'scans', 'findings', 'finding_observations', 'breach_exposures', 'reports'
  ]
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())',
      t);
  END LOOP;
END $$;

-- audit_log: tenants may read their own rows; anyone with INSERT may append.
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_read_own   ON audit_log FOR SELECT USING (tenant_id = current_tenant());
CREATE POLICY audit_append     ON audit_log FOR INSERT WITH CHECK (true);

-- ---------------------------------------------------------------------
-- View for the "fix this first" list (respects the caller's RLS)
-- ---------------------------------------------------------------------

CREATE VIEW v_fix_first WITH (security_invoker = true) AS
SELECT
  f.tenant_id,
  f.domain_id,
  f.id AS finding_id,
  cd.check_key,
  cd.title,
  cd.plain_explanation,
  cd.why_it_matters,
  cd.fix_steps,
  cd.effort,
  cd.owner_hint,
  f.severity,
  f.score,
  CASE WHEN f.score >= 7 THEN 'fix_now'
       WHEN f.score >= 4 THEN 'fix_this_month'
       ELSE 'plan_later' END AS tier,
  row_number() OVER (
    PARTITION BY f.domain_id
    ORDER BY f.score DESC,
             CASE cd.effort WHEN 'minutes' THEN 1 WHEN 'hours' THEN 2 ELSE 3 END
  ) AS fix_rank
FROM findings f
JOIN check_definitions cd ON cd.id = f.check_definition_id
WHERE f.status = 'open';

-- ---------------------------------------------------------------------
-- Least-privilege roles (attach LOGIN roles with strong credentials out of band)
-- Neither role has BYPASSRLS, so the policies above always apply.
-- ---------------------------------------------------------------------

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_api') THEN
    CREATE ROLE app_api NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scanner_worker') THEN
    CREATE ROLE scanner_worker NOLOGIN;
  END IF;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON
  tenants, users, memberships, subscriptions, domains, domain_verifications, assets,
  scans, findings, finding_observations, breach_exposures, reports, teaser_scans
  TO app_api;
GRANT SELECT ON plans, check_definitions, scoring_models, v_fix_first TO app_api;
GRANT SELECT, INSERT ON audit_log TO app_api;

GRANT SELECT ON domains, plans, check_definitions, scoring_models TO scanner_worker;
GRANT SELECT, INSERT, UPDATE ON assets, scans, findings, breach_exposures TO scanner_worker;
GRANT SELECT, INSERT ON finding_observations, reports TO scanner_worker;
GRANT SELECT, UPDATE ON teaser_scans TO scanner_worker;
GRANT INSERT ON audit_log TO scanner_worker;

COMMIT;
