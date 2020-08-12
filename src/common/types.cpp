#include "duckdb/common/types.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/serializer.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/string_type.hpp"

#include <cmath>

using namespace std;

namespace duckdb {

const LogicalType LogicalType::INVALID = LogicalType(LogicalTypeId::INVALID);
const LogicalType LogicalType::SQLNULL = LogicalType(LogicalTypeId::SQLNULL);
const LogicalType LogicalType::BOOLEAN = LogicalType(LogicalTypeId::BOOLEAN);
const LogicalType LogicalType::TINYINT = LogicalType(LogicalTypeId::TINYINT);
const LogicalType LogicalType::SMALLINT = LogicalType(LogicalTypeId::SMALLINT);
const LogicalType LogicalType::INTEGER = LogicalType(LogicalTypeId::INTEGER);
const LogicalType LogicalType::BIGINT = LogicalType(LogicalTypeId::BIGINT);
const LogicalType LogicalType::HUGEINT = LogicalType(LogicalTypeId::HUGEINT);
const LogicalType LogicalType::FLOAT = LogicalType(LogicalTypeId::FLOAT);
const LogicalType LogicalType::DOUBLE = LogicalType(LogicalTypeId::DOUBLE);
const LogicalType LogicalType::DATE = LogicalType(LogicalTypeId::DATE);
const LogicalType LogicalType::TIMESTAMP = LogicalType(LogicalTypeId::TIMESTAMP);
const LogicalType LogicalType::TIME = LogicalType(LogicalTypeId::TIME);

const LogicalType LogicalType::VARCHAR = LogicalType(LogicalTypeId::VARCHAR);
const LogicalType LogicalType::VARBINARY = LogicalType(LogicalTypeId::VARBINARY);

const LogicalType LogicalType::BLOB = LogicalType(LogicalTypeId::BLOB);
const LogicalType LogicalType::INTERVAL = LogicalType(LogicalTypeId::INTERVAL);

// TODO these are incomplete and should maybe not exist as such
const LogicalType LogicalType::STRUCT = LogicalType(LogicalTypeId::STRUCT);
const LogicalType LogicalType::LIST = LogicalType(LogicalTypeId::LIST);

const LogicalType LogicalType::ANY = LogicalType(LogicalTypeId::ANY);

const vector<LogicalType> LogicalType::NUMERIC = {
    LogicalType::TINYINT, LogicalType::SMALLINT, LogicalType::INTEGER, LogicalType::BIGINT, LogicalType::HUGEINT,
    LogicalType::FLOAT,   LogicalType::DOUBLE };

const vector<LogicalType> LogicalType::INTEGRAL = {LogicalType::TINYINT, LogicalType::SMALLINT, LogicalType::INTEGER, LogicalType::BIGINT, LogicalType::HUGEINT};

const vector<LogicalType> LogicalType::ALL_TYPES = {
    LogicalType::BOOLEAN, LogicalType::TINYINT,   LogicalType::SMALLINT, LogicalType::INTEGER, LogicalType::BIGINT,
    LogicalType::DATE,    LogicalType::TIMESTAMP, LogicalType::DOUBLE,   LogicalType::FLOAT,
    LogicalType::VARCHAR, LogicalType::BLOB, LogicalType::INTERVAL, LogicalType::HUGEINT};
// TODO add LIST/STRUCT here

const PhysicalType ROW_TYPE = PhysicalType::INT64;

string TypeIdToString(PhysicalType type) {
	switch (type) {
	case PhysicalType::BOOL:
		return "BOOL";
	case PhysicalType::INT8:
		return "INT8";
	case PhysicalType::INT16:
		return "INT16";
	case PhysicalType::INT32:
		return "INT32";
	case PhysicalType::INT64:
		return "INT64";
	case PhysicalType::INT128:
		return "INT128";
	case PhysicalType::HASH:
		return "HASH";
	case PhysicalType::POINTER:
		return "POINTER";
	case PhysicalType::FLOAT:
		return "FLOAT";
	case PhysicalType::DOUBLE:
		return "DOUBLE";
	case PhysicalType::VARCHAR:
		return "VARCHAR";
	case PhysicalType::VARBINARY:
		return "VARBINARY";
	case PhysicalType::INTERVAL:
		return "INTERVAL";
	case PhysicalType::STRUCT:
		return "STRUCT<?>";
	case PhysicalType::LIST:
		return "LIST<?>";
	default:
		throw ConversionException("Invalid PhysicalType %d", type);
	}
}

idx_t GetTypeIdSize(PhysicalType type) {
	switch (type) {
	case PhysicalType::BOOL:
		return sizeof(bool);
	case PhysicalType::INT8:
		return sizeof(int8_t);
	case PhysicalType::INT16:
		return sizeof(int16_t);
	case PhysicalType::INT32:
		return sizeof(int32_t);
	case PhysicalType::INT64:
		return sizeof(int64_t);
	case PhysicalType::INT128:
		return sizeof(hugeint_t);
	case PhysicalType::FLOAT:
		return sizeof(float);
	case PhysicalType::DOUBLE:
		return sizeof(double);
	case PhysicalType::HASH:
		return sizeof(hash_t);
	case PhysicalType::POINTER:
		return sizeof(uintptr_t);
	case PhysicalType::VARCHAR:
		return sizeof(string_t);
	case PhysicalType::INTERVAL:
		return sizeof(interval_t);
	case PhysicalType::STRUCT:
		return 0; // no own payload
	case PhysicalType::LIST:
		return 16; // offset + len
	case PhysicalType::VARBINARY:
		return sizeof(blob_t);
	default:
		throw ConversionException("Invalid PhysicalType %d", type);
	}
}

LogicalType LogicalTypeFromInternalType(PhysicalType type) {
	switch (type) {
	case PhysicalType::BOOL:
		return LogicalType(LogicalTypeId::BOOLEAN);
	case PhysicalType::INT8:
		return LogicalType::TINYINT;
	case PhysicalType::INT16:
		return LogicalType::SMALLINT;
	case PhysicalType::INT32:
		return LogicalType::INTEGER;
	case PhysicalType::INT64:
		return LogicalType::BIGINT;
	case PhysicalType::INT128:
		return LogicalType::HUGEINT;
	case PhysicalType::FLOAT:
		return LogicalType::FLOAT;
	case PhysicalType::DOUBLE:
		return LogicalType::DOUBLE;
	case PhysicalType::INTERVAL:
		return LogicalType::INTERVAL;
	case PhysicalType::VARCHAR:
		return LogicalType::VARCHAR;
	case PhysicalType::VARBINARY:
		return LogicalType(LogicalTypeId::VARBINARY);
	case PhysicalType::STRUCT:
		return LogicalType(LogicalTypeId::STRUCT); // TODO we do not know the child types here
	case PhysicalType::LIST:
		return LogicalType(LogicalTypeId::LIST);
	default:
		throw ConversionException("Invalid PhysicalType %d", type);
	}
}

bool TypeIsConstantSize(PhysicalType type) {
	return (type >= PhysicalType::BOOL && type <= PhysicalType::DOUBLE) ||
	       (type >= PhysicalType::FIXED_SIZE_BINARY && type <= PhysicalType::DECIMAL) || type == PhysicalType::HASH ||
	       type == PhysicalType::POINTER || type == PhysicalType::INTERVAL || type == PhysicalType::INT128;
}
bool TypeIsIntegral(PhysicalType type) {
	return (type >= PhysicalType::UINT8 && type <= PhysicalType::INT64) || type == PhysicalType::HASH || type == PhysicalType::POINTER || type == PhysicalType::INT128;
}
bool TypeIsNumeric(PhysicalType type) {
	return (type >= PhysicalType::UINT8 && type <= PhysicalType::DOUBLE)|| type == PhysicalType::INT128;
}
bool TypeIsInteger(PhysicalType type) {
	return (type >= PhysicalType::UINT8 && type <= PhysicalType::INT64) || type == PhysicalType::INT128;
}

void LogicalType::Serialize(Serializer &serializer) {
	serializer.Write(id);
	serializer.Write(width);
	serializer.Write(scale);
	serializer.WriteString(collation);
}

LogicalType LogicalType::Deserialize(Deserializer &source) {
	auto id = source.Read<LogicalTypeId>();
	auto width = source.Read<uint16_t>();
	auto scale = source.Read<uint8_t>();
	auto collation = source.Read<string>();
	return LogicalType(id, width, scale, collation);
}

string LogicalTypeIdToString(LogicalTypeId id) {
	switch (id) {
	case LogicalTypeId::BOOLEAN:
		return "BOOLEAN";
	case LogicalTypeId::TINYINT:
		return "TINYINT";
	case LogicalTypeId::SMALLINT:
		return "SMALLINT";
	case LogicalTypeId::INTEGER:
		return "INTEGER";
	case LogicalTypeId::BIGINT:
		return "BIGINT";
	case LogicalTypeId::HUGEINT:
		return "HUGEINT";
	case LogicalTypeId::DATE:
		return "DATE";
	case LogicalTypeId::TIME:
		return "TIME";
	case LogicalTypeId::TIMESTAMP:
		return "TIMESTAMP";
	case LogicalTypeId::FLOAT:
		return "FLOAT";
	case LogicalTypeId::DOUBLE:
		return "DOUBLE";
	case LogicalTypeId::DECIMAL:
		return "DECIMAL";
	case LogicalTypeId::VARCHAR:
		return "VARCHAR";
	case LogicalTypeId::BLOB:
		return "BLOB";
	case LogicalTypeId::VARBINARY:
		return "VARBINARY";
	case LogicalTypeId::CHAR:
		return "CHAR";
	case LogicalTypeId::INTERVAL:
		return "INTERVAL";
	case LogicalTypeId::SQLNULL:
		return "NULL";
	case LogicalTypeId::ANY:
		return "ANY";
	case LogicalTypeId::STRUCT:
		return "STRUCT<?>";
	case LogicalTypeId::LIST:
		return "LIST<?>";
	case LogicalTypeId::INVALID:
		return "INVALID";
	case LogicalTypeId::UNKNOWN:
		return "UNKNOWN";
	}
	return "UNDEFINED";
}

string LogicalTypeToString(LogicalType type) {
	// FIXME: display width/scale
	switch (type.id) {
	case LogicalTypeId::STRUCT: {
		string ret = "STRUCT<";
		for (size_t i = 0; i < type.child_type.size(); i++) {
			ret += type.child_type[i].first + ": " + LogicalTypeToString(type.child_type[i].second);
			if (i < type.child_type.size() - 1) {
				ret += ", ";
			}
		}
		ret += ">";
		return ret;
	}
	case LogicalTypeId::LIST: {
		if (type.child_type.size() == 0) {
			return "LIST<?>";
		}
		if (type.child_type.size() != 1) {
			throw Exception("List needs a single child element");
		}
		return "LIST<" + LogicalTypeToString(type.child_type[0].second) + ">";
	}
	default:
		return LogicalTypeIdToString(type.id);
	}
}

LogicalType TransformStringToLogicalType(string str) {
	auto lower_str = StringUtil::Lower(str);
	// Transform column type
	if (lower_str == "int" || lower_str == "int4" || lower_str == "signed" || lower_str == "integer" ||
	    lower_str == "integral" || lower_str == "int32") {
		return LogicalType::INTEGER;
	} else if (lower_str == "varchar" || lower_str == "bpchar" || lower_str == "text" || lower_str == "string" ||
	           lower_str == "char") {
		return LogicalType::VARCHAR;
	} else if (lower_str == "bytea" || lower_str == "blob") {
		return LogicalType::BLOB;
	} else if (lower_str == "int8" || lower_str == "bigint" || lower_str == "int64" || lower_str == "long") {
		return LogicalType::BIGINT;
	} else if (lower_str == "int2" || lower_str == "smallint" || lower_str == "short" || lower_str == "int16") {
		return LogicalType::SMALLINT;
	} else if (lower_str == "timestamp" || lower_str == "datetime") {
		return LogicalType::TIMESTAMP;
	} else if (lower_str == "bool" || lower_str == "boolean" || lower_str == "logical") {
		return LogicalType(LogicalTypeId::BOOLEAN);
	} else if (lower_str == "real" || lower_str == "float4" || lower_str == "float") {
		return LogicalType::FLOAT;
	} else if (lower_str == "double" || lower_str == "numeric" || lower_str == "float8" || lower_str == "decimal") {
		return LogicalType::DOUBLE;
	} else if (lower_str == "tinyint" || lower_str == "int1") {
		return LogicalType::TINYINT;
	} else if (lower_str == "varbinary") {
		return LogicalType(LogicalTypeId::VARBINARY);
	} else if (lower_str == "date") {
		return LogicalType::DATE;
	} else if (lower_str == "time") {
		return LogicalType::TIME;
	} else if (lower_str == "interval") {
		return LogicalType::INTERVAL;
	} else if (lower_str == "hugeint" || lower_str == "int128") {
		return LogicalType::HUGEINT;
	}  else {
		throw NotImplementedException("DataType %s not supported yet...\n", str.c_str());
	}
}

bool LogicalType::IsIntegral() const {
	switch (id) {
	case LogicalTypeId::TINYINT:
	case LogicalTypeId::SMALLINT:
	case LogicalTypeId::INTEGER:
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::HUGEINT:
		return true;
	default:
		return false;
	}
}

bool LogicalType::IsNumeric() const {
	switch (id) {
	case LogicalTypeId::TINYINT:
	case LogicalTypeId::SMALLINT:
	case LogicalTypeId::INTEGER:
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::HUGEINT:
	case LogicalTypeId::FLOAT:
	case LogicalTypeId::DOUBLE:
	case LogicalTypeId::DECIMAL:
		return true;
	default:
		return false;
	}
}

int NumericTypeOrder(PhysicalType type) {
	switch (type) {
	case PhysicalType::INT8:
		return 1;
	case PhysicalType::INT16:
		return 2;
	case PhysicalType::INT32:
		return 3;
	case PhysicalType::INT64:
		return 4;
	case PhysicalType::INT128:
		return 5;
	case PhysicalType::FLOAT:
		return 6;
	case PhysicalType::DOUBLE:
		return 7;
	default:
		throw NotImplementedException("Not a numeric type");
	}
}

bool LogicalType::IsMoreGenericThan(LogicalType &other) const {
	if (other.id == id) {
		return false;
	}

	if (other.id == LogicalTypeId::SQLNULL) {
		return true;
	}

	// all integer types can cast from INTEGER
	// this is because INTEGER is the smallest type considered by the automatic csv sniffer
	switch (id) {
	case LogicalTypeId::SMALLINT:
		switch (other.id) {
		case LogicalTypeId::TINYINT:
		case LogicalTypeId::SMALLINT:
		case LogicalTypeId::INTEGER:
			return true;
		default:
			return false;
		}
	case LogicalTypeId::INTEGER:
		switch (other.id) {
		case LogicalTypeId::TINYINT:
		case LogicalTypeId::SMALLINT:
		case LogicalTypeId::INTEGER:
			return true;
		default:
			return false;
		}
	case LogicalTypeId::BIGINT:
		switch (other.id) {
		case LogicalTypeId::TINYINT:
		case LogicalTypeId::SMALLINT:
		case LogicalTypeId::INTEGER:
			return true;
		default:
			return false;
		}
	case LogicalTypeId::HUGEINT:
		switch (other.id) {
		case LogicalTypeId::TINYINT:
		case LogicalTypeId::SMALLINT:
		case LogicalTypeId::INTEGER:
		case LogicalTypeId::BIGINT:
			return true;
		default:
			return false;
		}
	case LogicalTypeId::DOUBLE:
		switch (other.id) {
		case LogicalTypeId::TINYINT:
		case LogicalTypeId::SMALLINT:
		case LogicalTypeId::INTEGER:
		case LogicalTypeId::BIGINT:
			return true;
		default:
			return false;
		}
		return false;
	case LogicalTypeId::DATE:
		return false;
	case LogicalTypeId::TIMESTAMP:
		switch (other.id) {
		case LogicalTypeId::TIME:
		case LogicalTypeId::DATE:
			return true;
		default:
			return false;
		}
	case LogicalTypeId::VARCHAR:
		return true;
	default:
		return false;
	}

	return true;
}

PhysicalType GetInternalType(LogicalType type) {
	switch (type.id) {
	case LogicalTypeId::BOOLEAN:
		return PhysicalType::BOOL;
	case LogicalTypeId::TINYINT:
		return PhysicalType::INT8;
	case LogicalTypeId::SMALLINT:
		return PhysicalType::INT16;
	case LogicalTypeId::SQLNULL:
	case LogicalTypeId::DATE:
	case LogicalTypeId::TIME:
	case LogicalTypeId::INTEGER:
		return PhysicalType::INT32;
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::TIMESTAMP:
		return PhysicalType::INT64;
	case LogicalTypeId::HUGEINT:
		return PhysicalType::INT128;
	case LogicalTypeId::FLOAT:
		return PhysicalType::FLOAT;
	case LogicalTypeId::DOUBLE:
		return PhysicalType::DOUBLE;
	case LogicalTypeId::DECIMAL:
		// FIXME: for now
		return PhysicalType::DOUBLE;
	case LogicalTypeId::VARCHAR:
	case LogicalTypeId::CHAR:
	case LogicalTypeId::BLOB:
		return PhysicalType::VARCHAR;
	case LogicalTypeId::VARBINARY:
		return PhysicalType::VARBINARY;
	case LogicalTypeId::INTERVAL:
		return PhysicalType::INTERVAL;
	case LogicalTypeId::STRUCT:
		return PhysicalType::STRUCT;
	case LogicalTypeId::LIST:
		return PhysicalType::LIST;
	case LogicalTypeId::ANY:
		return PhysicalType::INVALID;
	default:
		throw ConversionException("Invalid LogicalType %s", LogicalTypeToString(type).c_str());
	}
}

LogicalType MaxLogicalType(LogicalType left, LogicalType right) {
	if (left.id < right.id) {
		return right;
	} else if (right.id < left.id) {
		return left;
	} else if (left.width > right.width || left.collation > right.collation) {
		return left;
	} else {
		return right;
	}
}

bool ApproxEqual(float ldecimal, float rdecimal) {
	float epsilon = fabs(rdecimal) * 0.01;
	return fabs(ldecimal - rdecimal) <= epsilon;
}

bool ApproxEqual(double ldecimal, double rdecimal) {
	double epsilon = fabs(rdecimal) * 0.01;
	return fabs(ldecimal - rdecimal) <= epsilon;
}

} // namespace duckdb
