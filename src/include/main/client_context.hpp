//===----------------------------------------------------------------------===//
//                         DuckDB
//
// main/client_context.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "catalog/catalog_set.hpp"
#include "execution/execution_context.hpp"
#include "main/query_profiler.hpp"
#include "main/stream_query_result.hpp"
#include "transaction/transaction_context.hpp"

namespace duckdb {
class DuckDB;

//! The ClientContext holds information relevant to the current client session
//! during execution
class ClientContext {
public:
	ClientContext(DuckDB &database);

	Transaction &ActiveTransaction() {
		return transaction.ActiveTransaction();
	}

	//! Interrupt execution of a query
	void Interrupt();
	//! Enable query profiling
	void EnableProfiling();
	//! Disable query profiling
	void DisableProfiling();
	
	//! Issue a query, returning a QueryResult. The QueryResult can be either a StreamQueryResult or a MaterializedQueryResult. The StreamQueryResult will only be returned in the case of a successful SELECT statement.
	unique_ptr<QueryResult> Query(string query, bool allow_stream_result);
	//! Fetch a query from the current result set (if any)
	unique_ptr<DataChunk> Fetch();
	//! Cleanup the result set (if any).
	void Cleanup();
	//! Invalidate the client context. The current query will be interrupted and the client context will be invalidated,
	//! making it impossible for future queries to run.
	void Invalidate();

	//! Query profiler
	QueryProfiler profiler;
	//! The database that this client is connected to
	DuckDB &db;
	//! Data for the currently running transaction
	TransactionContext transaction;
	//! Whether or not the query is interrupted
	bool interrupted;
	//! Whether or not the ClientContext has been invalidated because the underlying database is destroyed
	bool is_invalidated = false;
	//! Lock on using the ClientContext in parallel
	std::mutex context_lock;

	ExecutionContext execution_context;

	//	unique_ptr<CatalogSet> temporary_tables;
	unique_ptr<CatalogSet> prepared_statements;

#ifdef DEBUG
	// Whether or not aggressive query verification is enabled
	bool query_verification_enabled = false;
	//! Enable the running of optimizers
	bool enable_optimizer = true;
#endif
private:
	//! The currently opened StreamQueryResult (if any)
	StreamQueryResult *open_result = nullptr;


	//! Internal clean up, does not lock. Caller must hold the context_lock.
	void CleanupInternal();
	string FinalizeQuery(bool success);
	//! Internal fetch, does not lock. Caller must hold the context_lock.
	unique_ptr<DataChunk> FetchInternal();
	//! Internally execute a SQL statement. Caller must hold the context_lock.
	unique_ptr<QueryResult> ExecuteStatementInternal(string query, unique_ptr<SQLStatement> statement, bool allow_stream_result);
};
} // namespace duckdb
