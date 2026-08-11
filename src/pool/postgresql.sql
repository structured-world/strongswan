/* PostgreSQL reference schema for the sql, attr_sql and pool backends.
 * Mirrors mysql.sql: unsigned MySQL types map to the next wider signed
 * PostgreSQL type, varbinary/BLOB map to bytea, inline INDEX clauses become
 * named CREATE INDEX statements. */

DROP TABLE IF EXISTS identities;
CREATE TABLE identities (
  id serial PRIMARY KEY,
  type smallint NOT NULL,
  data bytea NOT NULL,
  UNIQUE (type, data)
);


DROP TABLE IF EXISTS child_configs;
CREATE TABLE child_configs (
  id serial PRIMARY KEY,
  name varchar(32) NOT NULL,
  lifetime integer NOT NULL default '1500',
  rekeytime integer NOT NULL default '1200',
  jitter integer NOT NULL default '60',
  updown varchar(128) default NULL,
  hostaccess smallint NOT NULL default '0',
  mode smallint NOT NULL default '2',
  start_action smallint NOT NULL default '0',
  dpd_action smallint NOT NULL default '0',
  close_action smallint NOT NULL default '0',
  ipcomp smallint NOT NULL default '0',
  reqid integer NOT NULL default '0'
);
CREATE INDEX child_configs_name ON child_configs (name);


DROP TABLE IF EXISTS child_config_traffic_selector;
CREATE TABLE child_config_traffic_selector (
  child_cfg integer NOT NULL,
  traffic_selector integer NOT NULL,
  kind smallint NOT NULL
);
CREATE INDEX child_config_traffic_selector_all ON child_config_traffic_selector (child_cfg, traffic_selector);


DROP TABLE IF EXISTS proposals;
CREATE TABLE proposals (
  id serial PRIMARY KEY,
  proposal varchar(128) NOT NULL
);


DROP TABLE IF EXISTS child_config_proposal;
CREATE TABLE child_config_proposal (
  child_cfg integer NOT NULL,
  prio integer NOT NULL,
  prop integer NOT NULL
);


DROP TABLE IF EXISTS ike_configs;
CREATE TABLE ike_configs (
  id serial PRIMARY KEY,
  certreq smallint NOT NULL default '1',
  force_encap smallint NOT NULL default '0',
  local varchar(128) NOT NULL,
  remote varchar(128) NOT NULL
);


DROP TABLE IF EXISTS ike_config_proposal;
CREATE TABLE ike_config_proposal (
  ike_cfg integer NOT NULL,
  prio integer NOT NULL,
  prop integer NOT NULL
);


DROP TABLE IF EXISTS peer_configs;
CREATE TABLE peer_configs (
  id serial PRIMARY KEY,
  name varchar(32) NOT NULL,
  ike_version smallint NOT NULL default '2',
  ike_cfg integer NOT NULL,
  local_id varchar(64) NOT NULL,
  remote_id varchar(64) NOT NULL,
  cert_policy smallint NOT NULL default '1',
  uniqueid smallint NOT NULL default '0',
  auth_method smallint NOT NULL default '1',
  eap_type smallint NOT NULL default '0',
  eap_vendor integer NOT NULL default '0',
  keyingtries smallint NOT NULL default '3',
  rekeytime integer NOT NULL default '7200',
  reauthtime integer NOT NULL default '0',
  jitter integer NOT NULL default '180',
  overtime integer NOT NULL default '300',
  mobike smallint NOT NULL default '1',
  dpd_delay integer NOT NULL default '120',
  virtual varchar(40) default NULL,
  pool varchar(32) default NULL,
  mediation smallint NOT NULL default '0',
  mediated_by integer NOT NULL default '0',
  peer_id integer NOT NULL default '0'
);
CREATE INDEX peer_configs_name ON peer_configs (name);


DROP TABLE IF EXISTS peer_config_child_config;
CREATE TABLE peer_config_child_config (
  peer_cfg integer NOT NULL,
  child_cfg integer NOT NULL,
  PRIMARY KEY (peer_cfg, child_cfg)
);


DROP TABLE IF EXISTS traffic_selectors;
CREATE TABLE traffic_selectors (
  id serial PRIMARY KEY,
  type smallint NOT NULL default '7',
  protocol integer NOT NULL default '0',
  start_addr bytea default NULL,
  end_addr bytea default NULL,
  start_port integer NOT NULL default '0',
  end_port integer NOT NULL default '65535'
);


DROP TABLE IF EXISTS certificates;
CREATE TABLE certificates (
  id serial PRIMARY KEY,
  type smallint NOT NULL,
  keytype smallint NOT NULL,
  data bytea NOT NULL
);


DROP TABLE IF EXISTS certificate_identity;
CREATE TABLE certificate_identity (
  certificate integer NOT NULL,
  identity integer NOT NULL,
  PRIMARY KEY (certificate, identity)
);


DROP TABLE IF EXISTS private_keys;
CREATE TABLE private_keys (
  id serial PRIMARY KEY,
  type smallint NOT NULL,
  data bytea NOT NULL
);


DROP TABLE IF EXISTS private_key_identity;
CREATE TABLE private_key_identity (
  private_key integer NOT NULL,
  identity integer NOT NULL,
  PRIMARY KEY (private_key, identity)
);


DROP TABLE IF EXISTS shared_secrets;
CREATE TABLE shared_secrets (
  id serial PRIMARY KEY,
  type smallint NOT NULL,
  data bytea NOT NULL
);


DROP TABLE IF EXISTS shared_secret_identity;
CREATE TABLE shared_secret_identity (
  shared_secret integer NOT NULL,
  identity integer NOT NULL,
  PRIMARY KEY (shared_secret, identity)
);


DROP TABLE IF EXISTS certificate_authorities;
CREATE TABLE certificate_authorities (
  id serial PRIMARY KEY,
  certificate integer NOT NULL
);


DROP TABLE IF EXISTS certificate_distribution_points;
CREATE TABLE certificate_distribution_points (
  id serial PRIMARY KEY,
  ca integer NOT NULL,
  type smallint NOT NULL,
  uri varchar(256) NOT NULL
);


DROP TABLE IF EXISTS pools;
CREATE TABLE pools (
  id serial PRIMARY KEY,
  name varchar(32) NOT NULL,
  start bytea NOT NULL,
  "end" bytea NOT NULL,
  timeout integer NOT NULL,
  UNIQUE (name)
);


DROP TABLE IF EXISTS addresses;
CREATE TABLE addresses (
  id serial PRIMARY KEY,
  pool integer NOT NULL,
  address bytea NOT NULL,
  identity integer NOT NULL DEFAULT 0,
  acquired integer NOT NULL DEFAULT 0,
  released integer NOT NULL DEFAULT 1
);
CREATE INDEX addresses_pool ON addresses (pool);
CREATE INDEX addresses_identity ON addresses (identity);
CREATE INDEX addresses_address ON addresses (address);


DROP TABLE IF EXISTS leases;
CREATE TABLE leases (
  id serial PRIMARY KEY,
  address integer NOT NULL,
  identity integer NOT NULL,
  acquired integer NOT NULL,
  released integer DEFAULT NULL
);


DROP TABLE IF EXISTS attribute_pools;
CREATE TABLE attribute_pools (
  id serial PRIMARY KEY,
  name varchar(32) NOT NULL
);


DROP TABLE IF EXISTS attributes;
CREATE TABLE attributes (
  id serial PRIMARY KEY,
  identity integer NOT NULL default '0',
  pool integer NOT NULL default '0',
  type integer NOT NULL,
  value bytea NOT NULL
);
CREATE INDEX attributes_identity ON attributes (identity);
CREATE INDEX attributes_pool ON attributes (pool);


DROP TABLE IF EXISTS ike_sas;
CREATE TABLE ike_sas (
  local_spi bytea NOT NULL PRIMARY KEY,
  remote_spi bytea NOT NULL,
  id integer NOT NULL,
  initiator smallint NOT NULL,
  local_id_type smallint NOT NULL,
  local_id_data bytea DEFAULT NULL,
  remote_id_type smallint NOT NULL,
  remote_id_data bytea DEFAULT NULL,
  host_family smallint NOT NULL,
  local_host_data bytea NOT NULL,
  remote_host_data bytea NOT NULL,
  lastuse timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);

/* PostgreSQL has no ON UPDATE CURRENT_TIMESTAMP; refresh lastuse with a
 * trigger so the sql_logger upsert keeps it current */
CREATE OR REPLACE FUNCTION ike_sas_touch_lastuse() RETURNS trigger AS $$
BEGIN
  NEW.lastuse := CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER ike_sas_lastuse BEFORE UPDATE ON ike_sas
  FOR EACH ROW EXECUTE FUNCTION ike_sas_touch_lastuse();


DROP TABLE IF EXISTS logs;
CREATE TABLE logs (
  id serial PRIMARY KEY,
  local_spi bytea NOT NULL,
  signal smallint NOT NULL,
  level smallint NOT NULL,
  msg varchar(256) NOT NULL,
  time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
