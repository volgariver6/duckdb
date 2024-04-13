#include "duckdb/parser/parsed_data/load_info.hpp"

namespace duckdb {

unique_ptr<LoadInfo> LoadInfo::Copy() const {
	auto result = make_uniq<LoadInfo>();
	result->filename = filename;
	result->repository = repository;
	result->load_type = load_type;
	return result;
}

static LoadInfoToString(load_type) {
	switch (load_type) {
	case LoadType::LOAD:
		return "LOAD";
	case LoadType::INSTALL:
		return "INSTALL";
	case LoadType::FORCE_INSTALL:
		return "FORCE INSTALL";
	default:
		throw InternalException("ToString for LoadType with type: %s not implemented", EnumUtil::ToString(load_type));
	}
}

string LoadInfo::ToString() const {
	string result = "";
	result += LoadInfoToString(load_type);
	result += StringUtil::Format(" '%s'", filename);
	if (!repository.empty()) {
		result += " FROM " + repository;
	}
	result += ";";
	return result;
}

} // namespace duckdb
