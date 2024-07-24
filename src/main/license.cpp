#include <ctime>
#include <cstring>
#include <iostream>
#include <fstream>
#include <regex>
#include <utility>

#include "openssl/pem.h"
#include "openssl/evp.h"
#include "openssl/sha.h"
#include "openssl/bio.h"
#include "openssl/buffer.h"

#include "duckdb/main/license.hpp"

namespace duckdb {

using namespace std;

// The commands to generate private and public key:
// openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096
// openssl rsa -pubout -in private_key.pem -out public_key.pem
const char *privKeyContent = "-----BEGIN PRIVATE KEY-----\n"
"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\n"
"qkY6dkSbLvmI3iWMmP4Fikqh54O3rg==\n"
"-----END PRIVATE KEY-----";

const char *pubKeyContent = "-----BEGIN PUBLIC KEY-----\n"
"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAk3o/Uv41zOjQ0SYvFMJu\n"
"BF13Au2z67rMDQxDhmaEvMVH0zEDZ1AR8xoYFMOL0MG9tA1LzoEUPaYTBhGGOH0P\n"
"x8t8A2MPlmPPIMkao/l076VWDS3Zv4ZpVsjfjx3Tr5/kWR+QqHI0XTjjo++Qbw3O\n"
"/QznwF6MfbEdeUTsI0eE1vTzN+2+gDq46cdTKaqqiwKpSbfnITilkFPNpG2SaWq6\n"
"Cw+/WvwNRs+cGgwBXj3Ue6Wf8qqNUTV2HxMXIMLRONhqWb8LclQws6J/ZpVxazrx\n"
"hRW/3KFIGrfdb8d0J2m8UNxZOD+IRoXKBb2QrCycEGxR3rg+GJdjB0ZsuOJ+xyw9\n"
"dDPGW/pIWJsVNiioXX1mDr051OgTEgU4Jvv/oqFmSLixuCVsvAtmEOqkrR6eP/BU\n"
"nKFwQFV6roul9ars8mAbSEV30qszxLn+Xkalkr5piR0jlQqy/6Zdqo9BKdlrVwf0\n"
"Q/RogznTYryhEiXNcgwdKwlfXXI/M68vkxbqLA+rbOF1L8aTGtOR1FhQBmbcd9bx\n"
"d1ILIBbC2px7YxhZFjQYAqxZXgCxYc/N7JPo4oOyhdO3iEFnhHLfL6p4eYvM0Rfv\n"
"BXPGIYAxD4NGmB8xoG5q39+kkQ77cTtMg7n92ypqkQ8nV5NPzBpekatR4ok1WrRR\n"
"8ISpSmVitMFQDSiJQ0QXhAkCAwEAAQ==\n"
"-----END PUBLIC KEY-----";

License::License(int days, const string& mac_addr) : days(days), commercial(true) {
	regex mac_regex("^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$");
	if (regex_match(mac_addr, mac_regex)) {
		this->mac_addr = mac_addr;
		commercial = true;
	} else {
		throw invalid_argument("Invalid MAC address format: " + mac_addr);
	}
}

License::License(int days) : days(days), commercial(false) {
}

License::License(const char *lic_param) {
    if (!lic_param) {
        MakeDefault();
        return;
    }
	string input_str(lic_param);
	size_t semicolon_pos = input_str.find('|');
	if (semicolon_pos != string::npos) {
		string number_str = input_str.substr(0, semicolon_pos);
		try {
			days = stoi(number_str);
		} catch (const invalid_argument& e) {
			throw invalid_argument("Invalid integer format: " + number_str);
		}

		string mac_address_str = input_str.substr(semicolon_pos + 1);
		regex mac_regex("^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$");
		if (regex_match(mac_address_str, mac_regex)) {
			mac_addr = mac_address_str;
			commercial = true;
		} else {
			throw invalid_argument("Invalid MAC address format: " + mac_address_str);
		}
	} else {
		commercial = false;
		try {
			days = stoi(input_str);
			if (days > MAX_DAYS_NOT_COMMERCIAL) {
				days = MAX_DAYS_NOT_COMMERCIAL;
			}
		} catch (const invalid_argument& e) {
			throw invalid_argument("Invalid integer format: " + input_str);
		}
	}
}

License::~License() = default;

string base64Encode(vector<unsigned char>& input) {
	BIO* bio = BIO_new(BIO_f_base64());
	BIO* bmem = BIO_new(BIO_s_mem());
	bio = BIO_push(bio, bmem);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, input.data(), int(input.size()));
	BIO_flush(bio);

	BUF_MEM* bptr;
	BIO_get_mem_ptr(bio, &bptr);

	string output(bptr->data, bptr->length);
	BIO_free_all(bio);

	return output;
}

vector<unsigned char> base64Decode(const string& input) {
	BIO* bio = BIO_new_mem_buf(input.data(), int(input.size()));
	BIO* b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	vector<unsigned char> output(input.size());
	int decodedLength = BIO_read(bio, output.data(), int(input.size()));
	output.resize(decodedLength);

	BIO_free_all(bio);
	return output;
}

EVP_PKEY* loadPubKeyFromString(const string &pubKeyStr) {
	BIO* bio = BIO_new_mem_buf(pubKeyStr.data(), int(pubKeyStr.size()));
	EVP_PKEY* pubKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	return pubKey;
}

EVP_PKEY* loadPrivKeyFromString(const string &privKeyStr) {
	BIO* bio = BIO_new_mem_buf(privKeyStr.data(), int(privKeyStr.size()));
	EVP_PKEY* privKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	return privKey;
}

string encryptRSA(const string &plaintext, const string &pubKeyStr) {
	EVP_PKEY* pubKey = loadPubKeyFromString(pubKeyStr);
	if (!pubKey) {
		cerr << "Error reading public key" << endl;
		return "";
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubKey, nullptr);
	if (!ctx) {
		cerr << "Error creating context" << endl;
		EVP_PKEY_free(pubKey);
		return "";
	}

	if (EVP_PKEY_encrypt_init(ctx) <= 0) {
		cerr << "Error initializing encryption" << endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pubKey);
		return "";
	}

	size_t outlen;
	if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, (unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) {
		cerr << "Error calculating encrypted length" << endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pubKey);
		return "";
	}

	vector<unsigned char> encrypted(outlen);
	if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outlen, (unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) {
		cerr << "Error encrypting message" << endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pubKey);
		return "";
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pubKey);

	return base64Encode(encrypted);
}

string decryptRSA(const string &cipherText, const string &privKeyStr) {
	EVP_PKEY* privKey = loadPrivKeyFromString(privKeyStr);
	if (!privKey) {
		cerr << "Error reading private key" << endl;
		return "";
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey, nullptr);
	if (!ctx) {
		cerr << "Error creating context" << endl;
		EVP_PKEY_free(privKey);
		return "";
	}

	if (EVP_PKEY_decrypt_init(ctx) <= 0) {
		cerr << "Error initializing decryption" << endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(privKey);
		return "";
	}

	size_t outlen;
	if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, (unsigned char*)cipherText.c_str(), cipherText.size()) <= 0) {
		cerr << "Error calculating decrypted length" << endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(privKey);
		return "";
	}

	vector<unsigned char> decrypted(outlen);
	if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outlen, (unsigned char*)cipherText.c_str(), cipherText.size()) <= 0) {
		cerr << "Error decrypting message" << endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(privKey);
		return "";
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(privKey);

	return {(char*)decrypted.data(), outlen};
}

void License::Generate() const {
	time_t valid = time(nullptr) + days * 24 * 60 * 60;
	struct tm *locTime = localtime(&valid);
	uint32_t year = locTime->tm_year + 1900;
	uint8_t month = uint8_t(locTime->tm_mon) + 1;
	auto day = uint8_t(locTime->tm_mday);

	char pText[256];
	bzero(pText, 256);
	char *ptr = reinterpret_cast<char *>(pText);

	// write the days
	memcpy(ptr, &year, 4);
	ptr += 4;
	*ptr = char(month);
	ptr++;
	*ptr = char(day);
	ptr++;

	// write if it is commercial and mac address.
	if (commercial) {
		*ptr = 1;
		ptr++;
		strcpy(ptr, mac_addr.data());
		ptr += mac_addr.size();
	} else {
		*ptr = 0;
		ptr++;
	}
	auto len = ptr - pText;
	ptr = reinterpret_cast<char *>(pText);

	string encryptedText = encryptRSA(string(ptr, len), pubKeyContent);
	cout << encryptedText << endl;
}

 bool License::Validate(string &license_path) {
	ifstream ifs;
	ifs.open(license_path, ios::in);
	string buf;
	while (getline(ifs, buf)) {
		auto data = base64Decode(buf);
		string line(data.begin(), data.end());
		if (line.empty()) {
			continue;
		}
		if (line[0] == '#') {
			continue;
		}
		if (ValidateLine(line)) {
			return true;
		}
	}
	ifs.close();
	return false;
}

string exec(const char* cmd) {
	array<char, 128> buffer{};
	string result;
	unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
	if (!pipe) {
		throw runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result.append(buffer.data());
	}
	return result;
}

bool isMACAddressMatch(const char *target_mac_str) {
	string target_mac = target_mac_str;
	string cmd_output = exec("ifconfig");

	smatch match;
	regex mac_regex("([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})");
	string::const_iterator search_start(cmd_output.cbegin());
	while (regex_search(search_start, cmd_output.cend(), match, mac_regex)) {
		string found_mac = match[0];
		transform(found_mac.begin(), found_mac.end(), found_mac.begin(), ::tolower);
		if (found_mac == target_mac) {
			return true;
		}
		search_start = match.suffix().first;
	}

	return false;
}

bool License::ValidateLine(string &line) {
	auto lic = decryptRSA(line, privKeyContent);
	auto content = lic.data();
	auto ptr = content;
	uint32_t year;
	memcpy(&year, ptr, 4);
	ptr += 4;
	uint8_t month = *ptr;
	ptr++;
	uint8_t day = *ptr;
	ptr++;

	// current time
	time_t valid = time(nullptr);
	struct tm *locTime = localtime(&valid);
	uint32_t current_year = locTime->tm_year + 1900;
	uint8_t current_month = uint8_t(locTime->tm_mon) + 1;
	auto current_day = uint8_t(locTime->tm_mday);

	if (year < current_year) {
		return false;
	}
	if (year == current_year && month < current_month) {
		return false;
	}
	if (year == current_year && month == current_month && day < current_day) {
		return false;
	}

	char mac[18];
	bzero(mac, 18);
	if (*ptr == 1) { // commercial, check the mac
		ptr++;
		strncpy(mac, ptr, 17);
		return isMACAddressMatch(mac);
	}
	return true;
}

void License::MakeDefault() {
    days = 7;
}

} // namespace duckdb