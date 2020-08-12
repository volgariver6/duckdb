//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/execution/operator/schema/physical_drop.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/execution/physical_operator.hpp"
#include "duckdb/parser/parsed_data/drop_info.hpp"

namespace duckdb {

//! PhysicalDrop represents a DROP [...] command
class PhysicalDrop : public PhysicalOperator {
public:
	PhysicalDrop(unique_ptr<DropInfo> info)
	    : PhysicalOperator(PhysicalOperatorType::DROP, {PhysicalType::BOOL}), info(move(info)) {
	}

	unique_ptr<DropInfo> info;

public:
	void GetChunkInternal(ExecutionContext &context, DataChunk &chunk, PhysicalOperatorState *state) override;
};

} // namespace duckdb
