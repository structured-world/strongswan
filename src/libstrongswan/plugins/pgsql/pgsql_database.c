/*
 * Copyright (C) 2025 Lantec / ULA Software
 * Based on mysql_database.c by Martin Willi, Tobias Brunner
 *
 * PostgreSQL database backend for strongSwan
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "pgsql_database.h"

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libpq-fe.h>

#include <utils/debug.h>
#include <utils/chunk.h>
#include <threading/thread_value.h>
#include <threading/mutex.h>
#include <collections/linked_list.h>

typedef struct private_pgsql_database_t private_pgsql_database_t;

/**
 * Private data of pgsql_database
 */
struct private_pgsql_database_t {

	/**
	 * Public interface
	 */
	pgsql_database_t public;

	/**
	 * Connection pool, contains conn_t
	 */
	linked_list_t *pool;

	/**
	 * Thread-specific transaction, as transaction_t
	 */
	thread_value_t *transaction;

	/**
	 * Mutex to lock pool
	 */
	mutex_t *mutex;

	/**
	 * Connection string for PostgreSQL
	 */
	char *conninfo;

};

typedef struct conn_t conn_t;

/**
 * Connection pool entry
 */
struct conn_t {

	/**
	 * PostgreSQL connection handle
	 */
	PGconn *conn;

	/**
	 * Connection in use?
	 */
	bool in_use;
};

/**
 * Database transaction
 */
typedef struct {

	/**
	 * Reference to the specific connection we started the transaction on
	 */
	conn_t *conn;

	/**
	 * Refcounter if transaction() is called multiple times
	 */
	refcount_t refs;

	/**
	 * TRUE if transaction was rolled back
	 */
	bool rollback;

} transaction_t;

/**
 * Release a postgresql connection
 */
static void conn_release(private_pgsql_database_t *this, conn_t *conn)
{
	/* do not release the connection while transactions are using it */
	if (!this->transaction->get(this->transaction))
	{
		this->mutex->lock(this->mutex);
		conn->in_use = FALSE;
		this->mutex->unlock(this->mutex);
	}
}

/**
 * Destroy a transaction and release the connection
 */
static void transaction_destroy(private_pgsql_database_t *this,
								transaction_t *trans)
{
	conn_release(this, trans->conn);
	free(trans);
}

/**
 * PostgreSQL library initialization
 */
bool pgsql_database_init()
{
	/* libpq doesn't require explicit initialization */
	return TRUE;
}

/**
 * PostgreSQL library cleanup
 */
void pgsql_database_deinit()
{
	/* libpq doesn't require explicit cleanup */
}

/**
 * Destroy a postgresql connection
 */
static void conn_destroy(conn_t *this)
{
	PQfinish(this->conn);
	free(this);
}

/**
 * Acquire/Reuse a postgresql connection
 */
static conn_t *conn_get(private_pgsql_database_t *this, transaction_t **trans)
{
	conn_t *current, *found = NULL;
	enumerator_t *enumerator;
	transaction_t *transaction;

	transaction = this->transaction->get(this->transaction);
	if (transaction)
	{
		if (trans)
		{
			*trans = transaction;
		}
		return transaction->conn;
	}

	while (TRUE)
	{
		this->mutex->lock(this->mutex);
		enumerator = this->pool->create_enumerator(this->pool);
		while (enumerator->enumerate(enumerator, &current))
		{
			if (!current->in_use)
			{
				found = current;
				found->in_use = TRUE;
				break;
			}
		}
		enumerator->destroy(enumerator);
		this->mutex->unlock(this->mutex);
		if (found)
		{
			/* Check connection status, release if dead */
			if (PQstatus(found->conn) == CONNECTION_OK)
			{
				/* Also try a simple query to verify */
				PGresult *res = PQexec(found->conn, "SELECT 1");
				if (PQresultStatus(res) == PGRES_TUPLES_OK)
				{
					PQclear(res);
					break;
				}
				PQclear(res);
			}
			/* Connection is dead, remove it */
			this->mutex->lock(this->mutex);
			this->pool->remove(this->pool, found, NULL);
			this->mutex->unlock(this->mutex);
			conn_destroy(found);
			found = NULL;
			continue;
		}
		break;
	}

	if (found == NULL)
	{
		INIT(found,
			.in_use = TRUE,
			.conn = PQconnectdb(this->conninfo),
		);

		if (PQstatus(found->conn) != CONNECTION_OK)
		{
			DBG1(DBG_LIB, "connecting to postgresql failed: %s",
				 PQerrorMessage(found->conn));
			conn_destroy(found);
			found = NULL;
		}
		else
		{
			this->mutex->lock(this->mutex);
			this->pool->insert_last(this->pool, found);
			DBG2(DBG_LIB, "increased PostgreSQL connection pool size to %d",
				 this->pool->get_count(this->pool));
			this->mutex->unlock(this->mutex);
		}
	}
	return found;
}

/**
 * Convert strongSwan SQL with ? placeholders to PostgreSQL $1, $2, etc.
 * Also counts parameters.
 */
static char *convert_sql(const char *sql, int *param_count)
{
	int count = 0, param_num = 0;
	const char *src = sql;
	char *result, *dst;
	size_t len = strlen(sql);
	size_t remaining;

	/* First pass: count placeholders */
	while (*src)
	{
		if (*src == '?')
		{
			count++;
		}
		src++;
	}

	/* Allocate result buffer (each ? becomes $N, up to 5 extra chars per param
	 * to handle parameter numbers up to 9999) */
	result = malloc(len + count * 5 + 1);
	if (!result)
	{
		*param_count = 0;
		return NULL;
	}

	/* Second pass: convert */
	src = sql;
	dst = result;
	remaining = len + count * 5 + 1;
	while (*src)
	{
		if (*src == '?')
		{
			int written;
			param_num++;
			written = snprintf(dst, remaining, "$%d", param_num);
			if (written < 0 || (size_t)written >= remaining)
			{
				/* Should never happen - allocation provides 5 chars per param */
				free(result);
				*param_count = 0;
				return NULL;
			}
			dst += written;
			remaining -= written;
		}
		else
		{
			*dst++ = *src;
			remaining--;
		}
		src++;
	}
	*dst = '\0';
	*param_count = count;
	return result;
}

typedef struct {
	/** Implements enumerator_t */
	enumerator_t public;
	/** PostgreSQL database */
	private_pgsql_database_t *db;
	/** Query result */
	PGresult *result;
	/** Current row */
	int row;
	/** Total rows */
	int nrows;
	/** Number of columns */
	int ncols;
	/** Column types requested */
	db_type_t *col_types;
	/** Pooled connection handle */
	conn_t *conn;
} pgsql_enumerator_t;

METHOD(enumerator_t, pgsql_enumerator_destroy, void,
	pgsql_enumerator_t *this)
{
	PQclear(this->result);
	conn_release(this->db, this->conn);
	free(this->col_types);
	free(this);
}

METHOD(enumerator_t, pgsql_enumerator_enumerate, bool,
	pgsql_enumerator_t *this, va_list args)
{
	int i;

	if (this->row >= this->nrows)
	{
		return FALSE;
	}

	for (i = 0; i < this->ncols; i++)
	{
		char *value = PQgetvalue(this->result, this->row, i);
		int is_null = PQgetisnull(this->result, this->row, i);
		int len = PQgetlength(this->result, this->row, i);

		switch (this->col_types[i])
		{
			case DB_INT:
			{
				int *out = va_arg(args, int*);
				*out = is_null ? 0 : atoi(value);
				break;
			}
			case DB_UINT:
			{
				u_int *out = va_arg(args, u_int*);
				*out = is_null ? 0 : (u_int)strtoul(value, NULL, 10);
				break;
			}
			case DB_TEXT:
			{
				char **out = va_arg(args, char**);
				if (is_null)
				{
					*out = NULL;
				}
				else
				{
					/* Return pointer into internal PGresult buffer,
					 * valid until the enumerator (and PGresult) is destroyed,
					 * matching the MySQL plugin's behavior. */
					*out = (char*)value;
				}
				break;
			}
			case DB_BLOB:
			{
				chunk_t *out = va_arg(args, chunk_t*);
				if (is_null)
				{
					out->ptr = NULL;
					out->len = 0;
				}
				else
				{
					/* For binary data, we need to handle bytea format */
					if (PQfformat(this->result, i) == 1)
					{
						/* Binary format */
						out->ptr = malloc(len);
						if (!out->ptr)
						{
							DBG1(DBG_LIB, "malloc() failed for DB_BLOB");
							out->len = 0;
						}
						else
						{
							memcpy(out->ptr, value, len);
							out->len = len;
						}
					}
					else
					{
						/* Text format (escaped bytea) */
						size_t result_len;
						unsigned char *unescaped = PQunescapeBytea(
							(unsigned char*)value, &result_len);
						if (unescaped)
						{
							out->ptr = malloc(result_len);
							if (!out->ptr)
							{
								DBG1(DBG_LIB, "malloc() failed for DB_BLOB");
								out->len = 0;
							}
							else
							{
								memcpy(out->ptr, unescaped, result_len);
								out->len = result_len;
							}
							PQfreemem(unescaped);
						}
						else
						{
							out->ptr = NULL;
							out->len = 0;
						}
					}
				}
				break;
			}
			case DB_DOUBLE:
			{
				double *out = va_arg(args, double*);
				*out = is_null ? 0.0 : atof(value);
				break;
			}
			default:
				break;
		}
	}
	this->row++;
	return TRUE;
}

METHOD(database_t, query, enumerator_t*,
	private_pgsql_database_t *this, char *sql, ...)
{
	va_list args;
	conn_t *conn;
	pgsql_enumerator_t *enumerator = NULL;
	int param_count, ncols;
	char *pgsql;
	PGresult *result;

	conn = conn_get(this, NULL);
	if (!conn)
	{
		return NULL;
	}

	/* Convert SQL from ? to $N format */
	pgsql = convert_sql(sql, &param_count);
	if (!pgsql)
	{
		conn_release(this, conn);
		return NULL;
	}

	va_start(args, sql);

	/* Build parameter arrays */
	char **param_values = NULL;
	int *param_lengths = NULL;
	int *param_formats = NULL;
	chunk_t *blobs = NULL;
	int blob_count = 0;
	bool param_error = FALSE;

	if (param_count > 0)
	{
		param_values = calloc(param_count, sizeof(char*));
		param_lengths = calloc(param_count, sizeof(int));
		param_formats = calloc(param_count, sizeof(int));
		blobs = calloc(param_count, sizeof(chunk_t));

		for (int i = 0; i < param_count; i++)
		{
			db_type_t type = va_arg(args, db_type_t);
			switch (type)
			{
				case DB_INT:
				{
					int val = va_arg(args, int);
					param_values[i] = malloc(32);
					snprintf(param_values[i], 32, "%d", val);
					param_formats[i] = 0; /* text */
					break;
				}
				case DB_UINT:
				{
					u_int val = va_arg(args, u_int);
					param_values[i] = malloc(32);
					snprintf(param_values[i], 32, "%u", val);
					param_formats[i] = 0;
					break;
				}
				case DB_TEXT:
				{
					char *val = va_arg(args, char*);
					param_values[i] = val ? strdup(val) : NULL;
					param_formats[i] = 0;
					break;
				}
				case DB_BLOB:
				{
					chunk_t val = va_arg(args, chunk_t);
					if (val.ptr && val.len > 0)
					{
						param_values[i] = (char*)val.ptr;
						param_lengths[i] = val.len;
						param_formats[i] = 1; /* binary */
						blobs[blob_count++] = val;
					}
					else
					{
						param_values[i] = NULL;
					}
					break;
				}
				case DB_DOUBLE:
				{
					double val = va_arg(args, double);
					param_values[i] = malloc(64);
					snprintf(param_values[i], 64, "%f", val);
					param_formats[i] = 0;
					break;
				}
				case DB_NULL:
				{
					param_values[i] = NULL;
					break;
				}
				default:
					DBG1(DBG_LIB, "invalid parameter type %d", type);
					param_error = TRUE;
					break;
			}
			if (param_error)
			{
				break;
			}
		}
	}

	/* Abort on parameter error - cleanup allocated memory */
	if (param_error)
	{
		for (int i = 0; i < param_count && param_values; i++)
		{
			bool is_blob = FALSE;
			for (int j = 0; j < blob_count; j++)
			{
				if (param_values[i] == (char*)blobs[j].ptr)
				{
					is_blob = TRUE;
					break;
				}
			}
			if (!is_blob && param_values[i])
			{
				free(param_values[i]);
			}
		}
		free(param_values);
		free(param_lengths);
		free(param_formats);
		free(blobs);
		free(pgsql);
		va_end(args);
		conn_release(this, conn);
		return NULL;
	}

	/* Execute query */
	result = PQexecParams(conn->conn, pgsql, param_count,
		NULL, /* let PostgreSQL infer types */
		(const char * const *)param_values,
		param_lengths,
		param_formats,
		0 /* text results */
	);

	/* Free parameter memory (except blobs which are caller-owned) */
	for (int i = 0; i < param_count; i++)
	{
		bool is_blob = FALSE;
		for (int j = 0; j < blob_count; j++)
		{
			if (param_values[i] == (char*)blobs[j].ptr)
			{
				is_blob = TRUE;
				break;
			}
		}
		if (!is_blob && param_values[i])
		{
			free(param_values[i]);
		}
	}
	free(param_values);
	free(param_lengths);
	free(param_formats);
	free(blobs);
	free(pgsql);

	if (PQresultStatus(result) != PGRES_TUPLES_OK)
	{
		DBG1(DBG_LIB, "PostgreSQL query failed: %s",
			 PQerrorMessage(conn->conn));
		PQclear(result);
		conn_release(this, conn);
		va_end(args);
		return NULL;
	}

	/* Create enumerator */
	ncols = PQnfields(result);
	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _pgsql_enumerator_enumerate,
			.destroy = _pgsql_enumerator_destroy,
		},
		.db = this,
		.result = result,
		.row = 0,
		.nrows = PQntuples(result),
		.ncols = ncols,
		.col_types = calloc(ncols, sizeof(db_type_t)),
		.conn = conn,
	);

	/* Store expected column types */
	for (int i = 0; i < ncols; i++)
	{
		enumerator->col_types[i] = va_arg(args, db_type_t);
	}

	va_end(args);
	return (enumerator_t*)enumerator;
}

METHOD(database_t, execute, int,
	private_pgsql_database_t *this, int *rowid, char *sql, ...)
{
	va_list args;
	conn_t *conn;
	int param_count;
	char *pgsql;
	PGresult *result;
	int affected = -1;

	conn = conn_get(this, NULL);
	if (!conn)
	{
		return -1;
	}

	pgsql = convert_sql(sql, &param_count);
	if (!pgsql)
	{
		conn_release(this, conn);
		return -1;
	}

	va_start(args, sql);

	/* Build parameter arrays */
	char **param_values = NULL;
	int *param_lengths = NULL;
	int *param_formats = NULL;
	bool *param_is_libpq = NULL;
	bool param_error = FALSE;

	if (param_count > 0)
	{
		param_values = calloc(param_count, sizeof(char*));
		param_lengths = calloc(param_count, sizeof(int));
		param_formats = calloc(param_count, sizeof(int));
		param_is_libpq = calloc(param_count, sizeof(bool));

		for (int i = 0; i < param_count; i++)
		{
			db_type_t type = va_arg(args, db_type_t);
			switch (type)
			{
				case DB_INT:
				{
					int val = va_arg(args, int);
					param_values[i] = malloc(32);
					snprintf(param_values[i], 32, "%d", val);
					break;
				}
				case DB_UINT:
				{
					u_int val = va_arg(args, u_int);
					param_values[i] = malloc(32);
					snprintf(param_values[i], 32, "%u", val);
					break;
				}
				case DB_TEXT:
				{
					char *val = va_arg(args, char*);
					param_values[i] = val ? strdup(val) : NULL;
					break;
				}
				case DB_BLOB:
				{
					chunk_t val = va_arg(args, chunk_t);
					if (val.ptr && val.len > 0)
					{
						/* Escape bytea for text protocol */
						size_t escaped_len;
						param_values[i] = (char*)PQescapeByteaConn(
							conn->conn, val.ptr, val.len, &escaped_len);
						param_is_libpq[i] = TRUE;
					}
					else
					{
						param_values[i] = NULL;
					}
					break;
				}
				case DB_DOUBLE:
				{
					double val = va_arg(args, double);
					param_values[i] = malloc(64);
					snprintf(param_values[i], 64, "%f", val);
					break;
				}
				case DB_NULL:
				{
					param_values[i] = NULL;
					break;
				}
				default:
					DBG1(DBG_LIB, "invalid parameter type %d", type);
					param_error = TRUE;
					break;
			}
			if (param_error)
			{
				break;
			}
		}
	}

	/* Abort on parameter error - cleanup allocated memory */
	if (param_error)
	{
		for (int i = 0; i < param_count && param_values; i++)
		{
			if (param_values[i])
			{
				if (param_is_libpq && param_is_libpq[i])
				{
					PQfreemem(param_values[i]);
				}
				else
				{
					free(param_values[i]);
				}
			}
		}
		free(param_values);
		free(param_lengths);
		free(param_formats);
		free(param_is_libpq);
		free(pgsql);
		va_end(args);
		conn_release(this, conn);
		return -1;
	}

	/* For INSERT with RETURNING id */
	char *exec_sql = pgsql;
	bool need_returning = (rowid != NULL && strncasecmp(sql, "INSERT", 6) == 0);
	if (need_returning)
	{
		/* Append RETURNING id if not already present */
		if (!strcasestr(pgsql, "RETURNING"))
		{
			size_t len = strlen(pgsql) + 20;
			exec_sql = malloc(len);
			if (!exec_sql)
			{
				DBG1(DBG_LIB, "malloc() failed for RETURNING clause");
				exec_sql = pgsql; /* Fall back to original query */
			}
			else
			{
				snprintf(exec_sql, len, "%s RETURNING id", pgsql);
			}
		}
	}

	result = PQexecParams(conn->conn, exec_sql, param_count,
		NULL, (const char * const *)param_values, param_lengths, param_formats, 0);

	if (exec_sql != pgsql)
	{
		free(exec_sql);
	}

	/* Free parameters using appropriate deallocator */
	for (int i = 0; i < param_count; i++)
	{
		if (param_values[i])
		{
			if (param_is_libpq[i])
			{
				/* Memory from PQescapeByteaConn must use PQfreemem */
				PQfreemem(param_values[i]);
			}
			else
			{
				free(param_values[i]);
			}
		}
	}
	free(param_values);
	free(param_lengths);
	free(param_formats);
	free(param_is_libpq);
	free(pgsql);

	ExecStatusType status = PQresultStatus(result);
	if (status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK)
	{
		char *affected_str = PQcmdTuples(result);
		affected = affected_str[0] ? atoi(affected_str) : 0;

		if (rowid && status == PGRES_TUPLES_OK && PQntuples(result) > 0)
		{
			*rowid = atoi(PQgetvalue(result, 0, 0));
		}
	}
	else
	{
		DBG1(DBG_LIB, "PostgreSQL execute failed: %s",
			 PQerrorMessage(conn->conn));
	}

	PQclear(result);
	va_end(args);
	conn_release(this, conn);
	return affected;
}

METHOD(database_t, transaction, bool,
	private_pgsql_database_t *this, bool serializable)
{
	transaction_t *trans = NULL;
	conn_t *conn;
	PGresult *result;

	conn = conn_get(this, &trans);
	if (!conn)
	{
		return FALSE;
	}
	else if (trans)
	{
		ref_get(&trans->refs);
		return TRUE;
	}

	if (serializable)
	{
		result = PQexec(conn->conn,
			"BEGIN ISOLATION LEVEL SERIALIZABLE");
	}
	else
	{
		result = PQexec(conn->conn, "BEGIN");
	}

	if (PQresultStatus(result) != PGRES_COMMAND_OK)
	{
		DBG1(DBG_LIB, "starting transaction failed: %s",
			 PQerrorMessage(conn->conn));
		PQclear(result);
		conn_release(this, conn);
		return FALSE;
	}
	PQclear(result);

	INIT(trans,
		.conn = conn,
		.refs = 1,
	);
	this->transaction->set(this->transaction, trans);
	return TRUE;
}

static bool finalize_transaction(private_pgsql_database_t *this,
								 bool rollback)
{
	transaction_t *trans;
	const char *command = "COMMIT";
	bool success;
	PGresult *result;

	trans = this->transaction->get(this->transaction);
	if (!trans)
	{
		DBG1(DBG_LIB, "no database transaction found");
		return FALSE;
	}

	trans->rollback |= rollback;

	if (ref_put(&trans->refs))
	{
		if (trans->rollback)
		{
			command = "ROLLBACK";
		}
		result = PQexec(trans->conn->conn, command);
		success = (PQresultStatus(result) == PGRES_COMMAND_OK);
		PQclear(result);

		this->transaction->set(this->transaction, NULL);
		transaction_destroy(this, trans);
		return success;
	}
	return TRUE;
}

METHOD(database_t, commit_, bool,
	private_pgsql_database_t *this)
{
	return finalize_transaction(this, FALSE);
}

METHOD(database_t, rollback, bool,
	private_pgsql_database_t *this)
{
	return finalize_transaction(this, TRUE);
}

METHOD(database_t, get_driver, db_driver_t,
	private_pgsql_database_t *this)
{
	return DB_PGSQL;
}

METHOD(database_t, destroy, void,
	private_pgsql_database_t *this)
{
	this->transaction->destroy(this->transaction);
	this->pool->destroy_function(this->pool, (void*)conn_destroy);
	this->mutex->destroy(this->mutex);
	free(this->conninfo);
	free(this);
}

/**
 * Parse URI and build PostgreSQL connection string
 * Format: postgresql://user:pass@host:port/database
 */
static char *build_conninfo(const char *uri)
{
	char *username = NULL, *password = NULL, *host = NULL;
	char *port = NULL, *database = NULL;
	char *conninfo = NULL;
	char *uri_copy, *pos, *start, *colon;
	size_t len, offset;

	if (strncmp(uri, "postgresql://", 13) != 0)
	{
		return NULL;
	}

	uri_copy = strdup(uri + 13);
	if (!uri_copy)
	{
		DBG1(DBG_LIB, "strdup() failed for PostgreSQL URI");
		return NULL;
	}
	start = uri_copy;

	/* Parse user:pass@host:port/database */
	pos = strchr(start, '@');
	if (pos)
	{
		*pos = '\0';
		/* user:pass */
		colon = strchr(start, ':');
		if (colon)
		{
			*colon = '\0';
			username = start;
			password = colon + 1;
		}
		else
		{
			username = start;
		}
		start = pos + 1;
	}

	/* host:port/database */
	pos = strchr(start, '/');
	if (pos)
	{
		*pos = '\0';
		database = pos + 1;
	}

	pos = strchr(start, ':');
	if (pos)
	{
		*pos = '\0';
		host = start;
		port = pos + 1;
	}
	else
	{
		host = start;
	}

	/* Build conninfo string with snprintf for safety */
	len = 256;
	if (username) len += strlen(username);
	if (password) len += strlen(password);
	if (host) len += strlen(host);
	if (port) len += strlen(port);
	if (database) len += strlen(database);

	conninfo = malloc(len);
	if (!conninfo)
	{
		DBG1(DBG_LIB, "malloc() failed for conninfo string");
		free(uri_copy);
		return NULL;
	}

	offset = 0;
	if (host)
	{
		offset += snprintf(conninfo + offset, len - offset, "host=%s", host);
	}
	if (port)
	{
		offset += snprintf(conninfo + offset, len - offset, " port=%s", port);
	}
	if (database)
	{
		offset += snprintf(conninfo + offset, len - offset, " dbname=%s", database);
	}
	if (username)
	{
		offset += snprintf(conninfo + offset, len - offset, " user=%s", username);
	}
	if (password)
	{
		offset += snprintf(conninfo + offset, len - offset, " password=%s", password);
	}

	free(uri_copy);
	return conninfo;
}

/*
 * Create a pgsql_database instance
 */
pgsql_database_t *pgsql_database_create(char *uri)
{
	private_pgsql_database_t *this;
	conn_t *conn;

	if (strncmp(uri, "postgresql://", 13) != 0)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.db = {
				.query = _query,
				.execute = _execute,
				.transaction = _transaction,
				.commit = _commit_,
				.rollback = _rollback,
				.get_driver = _get_driver,
				.destroy = _destroy,
			},
		},
		.conninfo = build_conninfo(uri),
	);

	if (!this->conninfo)
	{
		DBG1(DBG_LIB, "parsing PostgreSQL URI '%s' failed", uri);
		free(this);
		return NULL;
	}

	this->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	this->pool = linked_list_create();
	this->transaction = thread_value_create(NULL);

	/* Check connectivity */
	conn = conn_get(this, NULL);
	if (!conn)
	{
		destroy(this);
		return NULL;
	}
	conn_release(this, conn);

	DBG1(DBG_LIB, "PostgreSQL database connection established");
	return &this->public;
}
