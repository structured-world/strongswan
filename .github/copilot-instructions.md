# Copilot Code Review Instructions

## Repository Context

This is the **Structured World Foundation fork** of strongSwan. The `sw` branch contains our modifications on top of upstream strongSwan.

## Our Changes (vs upstream)

1. **Socket permissions fix** (`src/libstrongswan/networking/streams/stream_service_unix.c`)
   - umask change: `S_IXUSR | S_IXGRP | S_IRWXO` instead of `S_IRWXO`
   - Creates sockets with 0660 permissions (no execute bit)

2. **PostgreSQL plugin** (`src/libstrongswan/plugins/pgsql/`)
   - Native PostgreSQL database support for SQL plugin
   - Files: pgsql_plugin.c/h, pgsql_database.c/h, Makefile.am

3. **Build system integration** for pgsql:
   - `configure.ac`: --enable-pgsql option, PKG_CHECK_MODULES for libpq
   - `src/libstrongswan/Makefile.am`: USE_PGSQL conditional
   - `src/libstrongswan/database/database.h`: DB_PGSQL enum
   - `src/libstrongswan/database/database.c`: "PostgreSQL" in ENUM names

## Review Guidelines

### For PRs to `sw` branch:

1. **Security**: Check for buffer overflows, SQL injection, memory leaks
2. **Compatibility**: Ensure changes don't break upstream compatibility
3. **Style**: Follow strongSwan coding style (K&R braces, tabs for indentation)
4. **Build system**: Verify configure.ac/Makefile.am changes are correct
5. **PostgreSQL plugin**: Verify proper libpq API usage and error handling

### Critical files to review carefully:

- `src/libstrongswan/plugins/pgsql/pgsql_database.c` - SQL queries, connection handling
- `configure.ac` - Build configuration must not break other plugins
- Any changes to `database.h` - Enum values must stay in sync

### Do NOT flag:

- Upstream code style differences (we follow upstream conventions)
- Missing documentation in C files (strongSwan style)
- Long functions (common in strongSwan codebase)

### DO flag:

- Hardcoded credentials or connection strings
- Missing NULL checks after malloc/memory allocation
- SQL queries without proper escaping (use PQescapeLiteral)
- Missing PQclear() calls after PQexec()
- Resource leaks (connections, results not freed)

