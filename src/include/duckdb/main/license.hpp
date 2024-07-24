//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/main/license.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/winapi.hpp"

namespace duckdb {

const int MAX_DAYS_NOT_COMMERCIAL = 90;

class License {
public:
	DUCKDB_API explicit License(int days);
	DUCKDB_API explicit License(int days, const string& mac_addr);
    DUCKDB_API explicit License(const char *lic_param);
    DUCKDB_API ~License();

public:
    DUCKDB_API void Generate() const;
    DUCKDB_API static bool Validate(string &license_path);

private:
    void MakeDefault();
	static bool ValidateLine(string &line);

private:
    // the valid days this Lib can be used.
    int days{};
    // mac_addr contains the MAC address of a device.
    string mac_addr;
	// if there is mac address in the license, it is commercial.
	bool commercial;
};
} // namespace duckdb
