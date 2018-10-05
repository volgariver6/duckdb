//===----------------------------------------------------------------------===//
//
//                         DuckDB
//
// common/types/tuple.hpp
//
// Author: Mark Raasveldt
//
//===----------------------------------------------------------------------===//

#include <memory>

#include "common/types/data_chunk.hpp"

namespace duckdb {

//! A tuple contains a byte reprensetation of a single tuple stored row-wise
struct Tuple {
	size_t size;
	std::unique_ptr<uint8_t[]> data;
};

class TupleSerializer {
  public:
	TupleSerializer(const std::vector<TypeId> &types, bool inline_varlength,
	                std::vector<size_t> columns = {});

	//! Serialize a DataChunk to a set of tuples. Memory is allocated for the
	//! tuple data.
	void Serialize(DataChunk &chunk, Tuple targets[]);
	//! Serialize a DataChunk to a set of memory locations
	void Serialize(DataChunk &chunk, uint8_t *targets[]);

	//! Returns the constant per-tuple size (only if the size is constant)
	inline size_t TupleSize() {
		assert(!inline_varlength || !has_variable_columns);
		return base_size;
	}

	//! Compares two tuples. Returns 0 if they are equal, or else returns an
	//! ordering of the tuples. Both should have been constructed by this
	//! TupleSerializer.
	int Compare(Tuple &a, Tuple &b);
	//! Compare two tuple locations in memory. Can only be called if either (1)
	//! inline varlength is FALSE OR (2) no variable length columns are there
	int Compare(const uint8_t *a, const uint8_t *b);

  private:
	//! Serialize a single column of a chunk with potential variable columns to
	//! the target tuples
	void SerializeColumn(DataChunk &chunk, uint8_t *targets[], size_t column,
	                     size_t offsets[]);
	//! Single a single column of a chunk
	void SerializeColumn(DataChunk &chunk, uint8_t *targets[], size_t column,
	                     size_t &offset);

	std::vector<size_t> type_sizes;
	//! The columns to use into the chunks
	std::vector<size_t> columns;
	//! Base size of tuples
	size_t base_size;
	//! Set of variable-length columns included in the set
	std::vector<bool> is_variable;
	//! Whether or not the Serializer contains variable-length columns
	bool has_variable_columns;
	//! Whether or not variable length columns should be inlined
	bool inline_varlength;
};

} // namespace duckdb
