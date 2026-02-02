# strongSwan PostgreSQL Plugin

This plugin provides PostgreSQL database connectivity for strongSwan, enabling the `sql` and `attr-sql` plugins to store and retrieve VPN configuration from a PostgreSQL database.

## Installation

### Ubuntu / Debian

```bash
# Add GPG key
curl -fsSL https://repo.sw.foundation/keys/sw.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/sw.gpg

# Add repository
echo "deb [signed-by=/etc/apt/keyrings/sw.gpg] https://repo.sw.foundation/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/sw.list

# Install
sudo apt update
sudo apt install libstrongswan-pgsql
```

**Supported versions:** Ubuntu 22.04 (jammy), Ubuntu 24.04 (noble)

### Fedora

```bash
# Add repository
sudo dnf config-manager --add-repo https://repo.sw.foundation/rpm/fc$(rpm -E %fedora)/sw.repo

# Install
sudo dnf install strongswan-pgsql
```

**Supported versions:** Fedora 40, 41, 42

## Configuration

### 1. Create PostgreSQL Database

```sql
-- Create database and user
CREATE USER strongswan WITH PASSWORD 'your_secure_password';
CREATE DATABASE strongswan OWNER strongswan;

-- Connect to the database
\c strongswan

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO strongswan;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO strongswan;
```

### 2. Initialize Database Schema

The SQL schema for strongSwan is included in the strongSwan source. You can find it at:
- `/usr/share/strongswan/templates/database/sql/tables.sql` (if available)
- Or download from [strongSwan GitHub](https://github.com/strongswan/strongswan/tree/master/src/pool/sql)

Example schema initialization:

```bash
psql -U strongswan -d strongswan -f /path/to/tables.sql
```

### 3. Configure strongSwan

Edit `/etc/strongswan.d/charon/pgsql.conf`:

```
pgsql {
    load = yes
}
```

Edit `/etc/strongswan.d/charon/sql.conf` (create if doesn't exist):

```
sql {
    load = yes
    database = postgresql://strongswan:your_secure_password@localhost/strongswan
}
```

### 4. Enable SQL Plugin

Edit `/etc/strongswan.conf` or `/etc/strongswan.d/charon.conf`:

```
charon {
    plugins {
        sql {
            database = postgresql://strongswan:password@localhost/strongswan
        }
    }
}
```

### 5. Restart strongSwan

```bash
sudo systemctl restart strongswan
# or
sudo ipsec restart
```

## Database Connection String Format

```
postgresql://[user]:[password]@[host]:[port]/[database]
```

Examples:
- `postgresql://strongswan:password@localhost/strongswan`
- `postgresql://vpn_user:secret@db.example.com:5432/vpn_db`

## Using with attr-sql Plugin

The `attr-sql` plugin allows assigning attributes (like DNS servers, split tunneling) from the database.

```sql
-- Example: Assign DNS server to clients
INSERT INTO attributes (type, value) VALUES (
    25, -- INTERNAL_IP4_DNS
    '10.0.0.1'
);

-- Example: Assign virtual IP pool
INSERT INTO addresses (pool_id, address) VALUES (
    1,
    '10.10.10.1'
);
```

## Using with sql Plugin

The `sql` plugin stores IKE credentials in the database.

```sql
-- Example: Add EAP user
INSERT INTO identities (type, data) VALUES (
    2, -- ID_RFC822_ADDR (email)
    'user@example.com'
);

INSERT INTO shared_secrets (type, data) VALUES (
    1, -- EAP
    'user_password'
);

INSERT INTO shared_secret_identity (shared_secret, identity) VALUES (
    1, 1
);
```

## Troubleshooting

### Check Plugin Loading

```bash
sudo ipsec statusall | grep -i pgsql
# or
sudo swanctl --stats
```

### Enable Debug Logging

Edit `/etc/strongswan.d/charon-logging.conf`:

```
charon {
    filelog {
        /var/log/charon.log {
            default = 2
            sql = 3
            lib = 2
        }
    }
}
```

### Common Issues

1. **Plugin not found**: Ensure the package is installed and `/etc/strongswan.d/charon/pgsql.conf` has `load = yes`

2. **Database connection failed**: Check PostgreSQL is running and credentials are correct:
   ```bash
   psql -U strongswan -h localhost -d strongswan
   ```

3. **Permission denied**: Ensure the strongswan user has proper database permissions:
   ```sql
   GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO strongswan;
   ```

## Security Recommendations

1. **Use strong passwords** for database authentication
2. **Restrict database access** to localhost or specific IPs
3. **Use SSL/TLS** for remote database connections
4. **Regular backups** of the VPN database
5. **Audit logging** enabled in PostgreSQL

## Links

- [strongSwan Documentation](https://docs.strongswan.org/)
- [SQL Plugin Documentation](https://docs.strongswan.org/docs/5.9/plugins/sql.html)
- [attr-sql Plugin Documentation](https://docs.strongswan.org/docs/5.9/plugins/attr-sql.html)
- [SW Foundation GitHub](https://github.com/structured-world/strongswan)

## Support

For issues and feature requests, please use:
- [GitHub Issues](https://github.com/structured-world/strongswan/issues)
