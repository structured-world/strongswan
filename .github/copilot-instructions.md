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

## Upstream Code Style (IMPORTANT)

strongSwan uses **mixed C89/C99 style**. The codebase is not strictly C89 — many files use C99 features. Our plugin follows patterns found in similar upstream plugins.

### Accepted patterns (do NOT flag):

```c
// C99 for-loop declarations - ALLOWED (common in upstream)
for (int i = 0; i < count; i++)

// Variables declared at point of use - ALLOWED
if (condition)
{
    char *ptr = get_value();
    // ...
}

// Variables declared mid-function - ALLOWED when near first use
void function(void)
{
    // ... some code ...

    int result = compute();  // OK - declared near use
}
```

### Reference: Upstream uses same patterns

See these upstream files for evidence of mixed style:
- `src/libstrongswan/plugins/mysql/mysql_database.c`
- `src/libstrongswan/plugins/sqlite/sqlite_database.c`
- `src/libcharon/plugins/vici/vici_query.c`

## Review Guidelines

### For PRs to `sw` branch:

1. **Security**: Check for buffer overflows, SQL injection, memory leaks
2. **Compatibility**: Ensure changes don't break upstream compatibility
3. **Build system**: Verify configure.ac/Makefile.am changes are correct
4. **PostgreSQL plugin**: Verify proper libpq API usage and error handling

### Critical files to review carefully:

- `src/libstrongswan/plugins/pgsql/pgsql_database.c` - SQL queries, connection handling, memory management
- `configure.ac` - Build configuration must not break other plugins
- Any changes to `database.h` - Enum values must stay in sync

### Do NOT flag (style issues):

- **C99 variable declarations** — `for (int i = ...)`, variables declared mid-function
- **Variable declaration placement** — strongSwan does NOT enforce strict C89 "all declarations at top"
- Missing documentation in C files (strongSwan style)
- Long functions (common in strongSwan codebase)
- K&R brace style variations

### DO flag (real issues):

- Hardcoded credentials or connection strings
- Missing NULL checks after malloc/calloc/strdup
- Memory leaks in error paths (allocated memory not freed before return)
- SQL queries without proper escaping (use PQescapeLiteral)
- Missing PQclear() calls after PQexec()
- Incorrect memory deallocation (free vs PQfreemem for libpq memory)
- Resource leaks (connections, results not freed)
- Buffer overflows (use snprintf, not strcat/sprintf)

## Fork Surface Area

When adding new paths to this fork, these files must be updated:
- `.github/workflows/codeql.yml` — trigger paths AND analysis scope
- `.github/CODEOWNERS` — ownership
- This file — "Our Changes" section above

Failure to update these creates security blind spots where new code won't be scanned.
