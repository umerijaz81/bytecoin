// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "DBsqlite3.hpp"
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include "PathTools.hpp"
#include "common/Invariant.hpp"
#include "common/Math.hpp"
#include "common/string.hpp"

using namespace platform;

void sqlite::check(int rc, const char *msg) {
	if (rc != SQLITE_OK)
		throw Error((msg ? msg : "") + common::to_string(rc));
}

void sqlite::Dbi::open_check_create(OpenMode open_mode, const std::string &fp, bool *created) {
	full_path = fp;
	sqlite::check(sqlite3_open_v2(platform::expand_path(full_path).c_str(),
	                  &handle,
	                  open_mode == OpenMode::O_READ_EXISTING
	                      ? SQLITE_OPEN_READONLY
	                      : open_mode == OpenMode::O_OPEN_EXISTING ? SQLITE_OPEN_READWRITE
	                                                               : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE),
	                  nullptr),
	    "sqlite3_open ");
	invariant(open_mode != OpenMode::O_CREATE_ALWAYS, "sqlite database does not support clearing existing data");
	if (open_mode == OpenMode::O_READ_EXISTING)
		exec("BEGIN TRANSACTION",
		    "modifying database impossible. Disk read-only or database used by other running instance?");
	else
		exec("BEGIN IMMEDIATE TRANSACTION",
		    "modifying database impossible. Disk read-only or database used by other running instance?");
	sqlite::Stmt stmt_get_tables;
	stmt_get_tables.prepare(*this, "SELECT name FROM sqlite_master WHERE type = 'table'");
	*created = !stmt_get_tables.step();
	if (open_mode == OpenMode::O_CREATE_NEW && !*created)
		throw ErrorDBExists("sqlite database " + full_path + " already exists and will not be overwritten");
	sqlite::check(sqlite3_busy_timeout(handle, 5000), "sqlite3_busy_timeout");  // ms
}

void sqlite::Dbi::exec(const char *statement, const char *err_msg) {
	auto rc = sqlite3_exec(handle, statement, nullptr, nullptr, nullptr);
	if (rc != SQLITE_OK)
		throw Error((err_msg ? err_msg : "") + std::string(" sqlite error code=") + common::to_string(rc) +
		            " for db path=" + full_path);
}
void sqlite::Dbi::commit_txn() {
	exec("COMMIT TRANSACTION", "saving database data failed. Disk unplugged or out of disk space?");
}
void sqlite::Dbi::begin_txn() {
	exec("BEGIN IMMEDIATE TRANSACTION",
	    "modifying database impossible. Disk read-only or database used by other running instance?");
	// TODO - if readonly, will throw
}

sqlite::Dbi::~Dbi() {
	sqlite3_close(handle);
	handle = nullptr;
}

void sqlite::Stmt::prepare(const Dbi &dbi, const char *statement) {
	sqlite::check(sqlite3_prepare_v2(dbi.handle, statement, -1, &handle, nullptr), statement);
}
void sqlite::Stmt::bind_blob(int position, const void *data, size_t size) const {
	sqlite::check(sqlite3_bind_blob(handle, position, data == nullptr ? "" : data, static_cast<int>(size), nullptr),
	    "sqlite3_bind_blob failed");
	// sqlite3_bind_blob uses nullptr as a NULL indicator. Empty arrays can have nullptr as a data().
}

bool sqlite::Stmt::step() const {
	auto rc = sqlite3_step(handle);
	if (rc == SQLITE_DONE)
		return false;
	if (rc != SQLITE_ROW)
		throw platform::sqlite::Error("Cursor step failed sqlite3_step in step_and_check " + common::to_string(rc));
	return true;
}

size_t sqlite::Stmt::column_bytes(int column) const {
	return static_cast<size_t>(sqlite3_column_bytes(handle, column));
}
const uint8_t *sqlite::Stmt::column_blob(int column) const {
	return reinterpret_cast<const uint8_t *>(sqlite3_column_blob(handle, column));
}

sqlite::Stmt::Stmt(Stmt &&other) noexcept { std::swap(handle, other.handle); }
sqlite::Stmt::~Stmt() {
	sqlite3_finalize(handle);
	handle = nullptr;
}

DBsqliteKV::DBsqliteKV(OpenMode open_mode, const std::string &full_path, uint64_t max_tx_size)
    : full_path(full_path + ".sqlite") {
	//	if ()
	//		throw platform::sqlite::Error("SQLite cannot be used in read-only mode for now");
	//	lmdb_check(::mdb_env_set_mapsize(db_env.handle, max_db_size), "mdb_env_set_mapsize ");
	//	std::cout << "sqlite3_libversion=" << sqlite3_libversion() << std::endl;
	//	create_directories_if_necessary(full_path);
	bool created = false;
	db_dbi.open_check_create(open_mode, platform::expand_path(this->full_path), &created);
	const char *expected_schema =
	    "CREATE TABLE kv_table(kk BLOB PRIMARY KEY COLLATE BINARY, vv BLOB NOT NULL) WITHOUT ROWID";
	if (created)
		db_dbi.exec(expected_schema);
	sqlite::Stmt stmt_schema;
	stmt_schema.prepare(db_dbi, "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'kv_table'");
	if (!stmt_schema.step())
		throw sqlite::Error("sqlite database is missing the expected kv_table schema");
	const size_t schema_size = stmt_schema.column_bytes(0);
	const auto *schema_data  = stmt_schema.column_blob(0);
	const std::string actual_schema(
	    schema_size == 0 ? "" : reinterpret_cast<const char *>(schema_data), schema_size);
	if (actual_schema != expected_schema || stmt_schema.step())
		throw sqlite::Error("sqlite database has an unexpected kv_table schema");
	stmt_get.prepare(db_dbi, "SELECT kk, vv FROM kv_table WHERE kk = ?");
	stmt_insert.prepare(db_dbi, "INSERT INTO kv_table (kk, vv) VALUES (?, ?)");
	stmt_update.prepare(db_dbi, "REPLACE INTO kv_table (kk, vv) VALUES (?, ?)");
	stmt_del.prepare(db_dbi, "DELETE FROM kv_table WHERE kk = ?");
}

size_t DBsqliteKV::test_get_approximate_size() const { return 0; }

size_t DBsqliteKV::get_approximate_items_count() const {
	return std::numeric_limits<size_t>::
	    max();  // Sqlite does full table scan on select count(*), we do not want that behavior
	            //	sqlite3_reset(stmt_select_star.handle);
	            //	auto rc = sqlite3_step(stmt_select_star.handle);
	            //	if (rc != SQLITE_ROW)
	            //		throw platform::sqlite::Error("DB::get_approximate_items_count failed sqlite3_step in get " +
	            // common::to_string(rc));
	            //	return common::integer_cast<size_t>(sqlite3_column_int64(stmt_select_star.handle, 0));
}

static const size_t max_key_size = 255;

DBsqliteKV::Cursor::Cursor(const DBsqliteKV *db,
    const sqlite::Dbi &db_dbi,
    const std::string &prefix,
    const std::string &middle,
    bool forward)
    : db(db), prefix(prefix) {
	std::string start  = prefix + middle;
	std::string finish = start;
	if (finish.size() < max_key_size)
		finish += std::string(max_key_size - finish.size(), char(0xff));  // char('~')
	const char *sql = forward ? "SELECT kk, vv FROM kv_table WHERE kk >= ? ORDER BY kk ASC"
	                          : "SELECT kk, vv FROM kv_table WHERE kk <= ? ORDER BY kk DESC";
	stmt_get.prepare(db_dbi, sql);
	stmt_get.bind_blob(1, forward ? start.data() : finish.data(), forward ? start.size() : finish.size());
	step_and_check();
}

void DBsqliteKV::Cursor::next() { step_and_check(); }

void DBsqliteKV::Cursor::erase() {
	if (is_end)
		return;  // Some precaution
	sqlite3_reset(stmt_get.handle);
	std::string my_key = prefix + suffix;
	const_cast<DBsqliteKV *>(db)->del(my_key, true);
	stmt_get.bind_blob(1, my_key.data(), my_key.size());
	step_and_check();
}

void DBsqliteKV::Cursor::step_and_check() {
	if (!stmt_get.step()) {
		data   = nullptr;
		size   = 0;
		is_end = true;
		suffix = std::string{};
		return;
	}
	size = stmt_get.column_bytes(0);
	data = reinterpret_cast<const char *>(sqlite3_column_blob(stmt_get.handle, 0));
	if (size == 0)
		data = "";
	std::string it_key(data, size);
	size = stmt_get.column_bytes(1);
	data = reinterpret_cast<const char *>(sqlite3_column_blob(stmt_get.handle, 1));
	if (size == 0)
		data = "";  // SQLite may return nullptr for a present zero-length BLOB.
	if (it_key.size() < prefix.size() ||
	    std::char_traits<char>::compare(prefix.data(), it_key.data(), prefix.size()) != 0) {
		data   = nullptr;
		size   = 0;
		is_end = true;
		suffix = std::string{};
		return;
	}
	suffix = std::string(it_key.data() + prefix.size(), it_key.size() - prefix.size());
}

std::string DBsqliteKV::Cursor::get_value_string() const { return std::string(data, size); }
common::BinaryArray DBsqliteKV::Cursor::get_value_array() const { return common::BinaryArray(data, data + size); }

DBsqliteKV::Cursor DBsqliteKV::begin(const std::string &prefix, const std::string &middle, bool forward) const {
	return Cursor(this, db_dbi, prefix, middle, forward);
}

DBsqliteKV::Cursor DBsqliteKV::rbegin(const std::string &prefix, const std::string &middle) const {
	return begin(prefix, middle, false);
}

void DBsqliteKV::commit_db_txn() {
	db_dbi.commit_txn();
	db_dbi.begin_txn();
}

static void put(sqlite::Stmt &stmt, const std::string &key, const void *data, size_t size) {
	invariant(data || size == 0, "");
	sqlite3_reset(stmt.handle);
	stmt.bind_blob(1, key.data(), key.size());
	stmt.bind_blob(2, data, size);
	invariant(!stmt.step(), "put returned rows");
}

void DBsqliteKV::put(const std::string &key, const common::BinaryArray &value, bool nooverwrite) {
	sqlite::Stmt &stmt = nooverwrite ? stmt_insert : stmt_update;
	::put(stmt, key, value.data(), value.size());
}

void DBsqliteKV::put(const std::string &key, const std::string &value, bool nooverwrite) {
	sqlite::Stmt &stmt = nooverwrite ? stmt_insert : stmt_update;
	::put(stmt, key, value.data(), value.size());
}

struct SQLiteValue {
	bool found;
	const unsigned char *data;
	size_t size;
};

static SQLiteValue get(const sqlite::Stmt &stmt, const std::string &key) {
	sqlite3_reset(stmt.handle);
	stmt.bind_blob(1, key.data(), key.size());
	if (!stmt.step())
		return {false, nullptr, 0};
	auto si = stmt.column_bytes(1);
	auto da = stmt.column_blob(1);
	if (si == 0)
		da = reinterpret_cast<const unsigned char *>("");
	return {true, da, si};
}

bool DBsqliteKV::get(const std::string &key, common::BinaryArray &value) const {
	auto result = ::get(stmt_get, key);
	if (!result.found)
		return false;
	value.assign(result.data, result.data + result.size);
	return true;
}

bool DBsqliteKV::get(const std::string &key, std::string &value) const {
	auto result = ::get(stmt_get, key);
	if (!result.found)
		return false;
	value.assign(result.data, result.data + result.size);
	return true;
}

void DBsqliteKV::del(const std::string &key, bool mustexist) {
	sqlite3_reset(stmt_del.handle);
	stmt_del.bind_blob(1, key.data(), key.size());
	invariant(!stmt_del.step(), "sqlite del returned rows");
	int deleted_rows = sqlite3_changes(db_dbi.handle);
	if (mustexist && deleted_rows != 1)
		throw platform::sqlite::Error("DB::del row does not exits");
}

std::string DBsqliteKV::to_ascending_key(uint32_t key) {
	char buf[32] = {};
	std::snprintf(buf, sizeof(buf), "%08X", key);
	return std::string(buf);
}

uint32_t DBsqliteKV::from_ascending_key(const std::string &key) {
	long long unsigned val = 0;
	if (sscanf(key.c_str(), "%llx", &val) != 1)
		throw std::runtime_error("from_ascending_key failed to convert key=" + key);
	// TODO - std::stoull(key, nullptr, 16) when Google updates NDK compiler
	return common::integer_cast<uint32_t>(val);
}

std::string DBsqliteKV::clean_key(const std::string &key) {
	std::string result = key;
	for (char &ch : result) {
		unsigned char uch = ch;
		if (uch >= 128)
			uch -= 128;
		if (uch == 127)
			uch = 'F';
		if (uch < 32)
			uch = '0' + uch;
		ch = uch;
	}
	return result;
}

void DBsqliteKV::delete_db(const std::string &path) {
	auto ep = platform::expand_path(path);
	std::remove((ep + ".sqlite-journal").c_str());
	std::remove((ep + ".sqlite-wal").c_str());
	std::remove((ep + ".sqlite-shm").c_str());
	std::remove((ep + ".sqlite").c_str());
}
void DBsqliteKV::backup_db(const std::string &path, const std::string &dst_path) {
	const std::string src_path = platform::expand_path(path + ".sqlite");
	const std::string dst_path_expanded = platform::expand_path(dst_path + ".sqlite");
	if (FILE *existing = std::fopen(dst_path_expanded.c_str(), "rb")) {
		std::fclose(existing);
		throw platform::sqlite::Error("sqlite backup destination already exists: " + dst_path_expanded);
	}

	sqlite3 *src = nullptr;
	sqlite3 *dst = nullptr;
	if (sqlite3_open_v2(src_path.c_str(), &src, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
		const std::string detail = src ? sqlite3_errmsg(src) : "out of memory";
		if (src)
			sqlite3_close(src);
		throw platform::sqlite::Error("sqlite backup source open failed: " + detail);
	}
	if (sqlite3_open_v2(
	        dst_path_expanded.c_str(), &dst, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
		const std::string detail = dst ? sqlite3_errmsg(dst) : "out of memory";
		if (dst)
			sqlite3_close(dst);
		sqlite3_close(src);
		throw platform::sqlite::Error("sqlite backup destination open failed: " + detail);
	}

	sqlite3_backup *backup = sqlite3_backup_init(dst, "main", src, "main");
	if (!backup) {
		const std::string detail = sqlite3_errmsg(dst);
		sqlite3_close(dst);
		sqlite3_close(src);
		std::remove(dst_path_expanded.c_str());
		throw platform::sqlite::Error("sqlite backup initialization failed: " + detail);
	}

	int result;
	unsigned busy_retries = 0;
	do {
		result = sqlite3_backup_step(backup, -1);
		if ((result == SQLITE_BUSY || result == SQLITE_LOCKED) && busy_retries++ < 500)
			sqlite3_sleep(10);
		else
			break;
	} while (true);
	const int finish_result = sqlite3_backup_finish(backup);
	const std::string detail = sqlite3_errmsg(dst);
	sqlite3_close(dst);
	sqlite3_close(src);
	if (result != SQLITE_DONE || finish_result != SQLITE_OK) {
		std::remove(dst_path_expanded.c_str());
		throw platform::sqlite::Error("sqlite backup failed: " + detail);
	}
}

int DBsqliteKV::run_crash_test_child(const std::string &mode, const std::string &path) {
	const std::string state_key = "Z";
	const std::string undo_key  = "z" + std::string(32, 'B');
	const std::string before    = "snapshot-before";
	const std::string after     = "snapshot-after";
	if (mode == "prepare") {
		delete_db(path);
		DBsqliteKV db(platform::O_CREATE_NEW, path);
		db.put(state_key, before, false);
		db.commit_db_txn();
		return 0;
	}
	if (mode == "wal-prepare") {
		delete_db(path);
		DBsqliteKV db(platform::O_CREATE_NEW, path);
		db.db_dbi.commit_txn();
		sqlite::Stmt journal_mode;
		journal_mode.prepare(db.db_dbi, "PRAGMA journal_mode=WAL");
		if (!journal_mode.step())
			throw sqlite::Error("SQLite did not return its requested WAL journal mode");
		const size_t mode_size = journal_mode.column_bytes(0);
		const auto *mode_data  = journal_mode.column_blob(0);
		const std::string actual_mode(
		    mode_size == 0 ? "" : reinterpret_cast<const char *>(mode_data), mode_size);
		if (actual_mode != "wal" || journal_mode.step())
			throw sqlite::Error("SQLite refused the requested WAL journal mode");
		db.db_dbi.begin_txn();
		db.put(state_key, before, false);
		db.commit_db_txn();
		std::_Exit(90);
	}
	if (mode == "wal-commit-after") {
		DBsqliteKV db(platform::O_OPEN_EXISTING, path);
		db.put(state_key, after, false);
		db.put(undo_key, before, true);
		db.commit_db_txn();
		std::_Exit(91);
	}
	if (mode == "wal-checkpoint") {
		DBsqliteKV db(platform::O_OPEN_EXISTING, path);
		db.db_dbi.commit_txn();
		db.db_dbi.exec("PRAGMA wal_checkpoint(TRUNCATE)", "SQLite WAL checkpoint failed");
		return 0;
	}
	if (mode == "full-state-write" || mode == "full-undo-write") {
		DBsqliteKV db(platform::O_OPEN_EXISTING, path);
		sqlite::Stmt page_count;
		page_count.prepare(db.db_dbi, "PRAGMA page_count");
		if (!page_count.step())
			throw sqlite::Error("SQLite did not return its page count");
		const size_t page_count_size = page_count.column_bytes(0);
		const auto *page_count_data  = page_count.column_blob(0);
		const std::string pages(page_count_size == 0 ? "" : reinterpret_cast<const char *>(page_count_data),
		    page_count_size);
		if (pages.empty() || page_count.step())
			throw sqlite::Error("SQLite returned an invalid page count");
		const std::string limit = "PRAGMA max_page_count=" + pages;
		db.db_dbi.exec(limit.c_str(), "setting SQLite disk-full page limit failed");
		const std::string oversized(1024 * 1024, 'F');
		const char *stage = mode == "full-state-write" ? "state" : "undo";
		try {
			if (mode == "full-state-write") {
				db.put(state_key, oversized, false);
			} else {
				db.put(state_key, after, false);
				db.put(undo_key, oversized, true);
			}
		} catch (const std::exception &) {
			const int code = sqlite3_extended_errcode(db.db_dbi.handle);
			std::cerr << "ONYX_DB_FULL stage=" << stage << " sqlite_code=" << code << std::endl;
			if ((code & 0xff) == SQLITE_FULL)
				std::_Exit(mode == "full-state-write" ? 92 : 93);
			return 94;
		}
		std::cerr << "ONYX_DB_FULL stage=" << stage << " sqlite_code=0 detail=no-failure" << std::endl;
		return 95;
	}
	if (mode == "crash-after-state-write" || mode == "crash-before-commit" ||
	    mode == "crash-after-commit") {
		DBsqliteKV db(platform::O_OPEN_EXISTING, path);
		db.put(state_key, after, false);
		if (mode == "crash-after-state-write")
			std::_Exit(85);
		db.put(undo_key, before, true);
		if (mode == "crash-before-commit")
			std::_Exit(86);
		db.commit_db_txn();
		std::_Exit(87);
	}
	if (mode == "probe-before" || mode == "probe-after") {
		try {
			DBsqliteKV db(platform::O_OPEN_EXISTING, path);
			std::string state;
			std::string undo;
			if (!db.get(state_key, state)) {
				std::cerr << "ONYX_DB_PROBE result=semantic-mismatch detail=missing-state" << std::endl;
				return 89;
			}
			const bool has_undo = db.get(undo_key, undo);
			const bool exact_before = state == before && !has_undo;
			const bool exact_after  = state == after && has_undo && undo == before;
			if ((mode == "probe-before" && exact_before) || (mode == "probe-after" && exact_after)) {
				std::cout << "ONYX_DB_PROBE result=exact" << std::endl;
				return 0;
			}
			std::cerr << "ONYX_DB_PROBE result=semantic-mismatch detail=state-undo-pair" << std::endl;
			return 89;
		} catch (const std::exception &error) {
			std::cerr << "ONYX_DB_PROBE result=adapter-failure detail=" << error.what() << std::endl;
			return 88;
		}
	}
	DBsqliteKV db(platform::O_OPEN_EXISTING, path);
	std::string state;
	std::string undo;
	if (!db.get(state_key, state))
		throw sqlite::Error("crash recovery lost the Onyx state key");
	const bool has_undo = db.get(undo_key, undo);
	if (mode == "verify-before") {
		if (state != before || has_undo)
			throw sqlite::Error("uncommitted Onyx state/undo writes survived process termination");
		return 0;
	}
	if (mode == "verify-after") {
		if (state != after || !has_undo || undo != before)
			throw sqlite::Error("committed Onyx state/undo pair was not recovered atomically");
		return 0;
	}
	throw sqlite::Error("unknown DB crash-test child mode: " + mode);
}

void DBsqliteKV::run_tests() {
	delete_db("temp_db");
	delete_db("temp_db_backup");
	for (const char *suffix : {".sqlite-journal", ".sqlite-wal", ".sqlite-shm"}) {
		const std::string sidecar = "temp_db" + std::string(suffix);
		FILE *file                = std::fopen(sidecar.c_str(), "wb");
		invariant(file != nullptr, "sqlite delete test could not create a disposable sidecar");
		std::fclose(file);
	}
	delete_db("temp_db");
	for (const char *suffix : {".sqlite-journal", ".sqlite-wal", ".sqlite-shm"}) {
		const std::string sidecar = "temp_db" + std::string(suffix);
		FILE *file                = std::fopen(sidecar.c_str(), "rb");
		if (file != nullptr)
			std::fclose(file);
		invariant(file == nullptr, "sqlite delete left a stale journal, WAL, or shared-memory sidecar");
	}
	{
		DBsqliteKV db(platform::O_CREATE_NEW, "temp_db");
		std::string str;
		bool res = db.get("history/ha", str);
		std::cout << "res=" << res << std::endl;

		db.put("history/ha", "ua", false);
		db.put("history/hb", "ub", false);
		db.put("history/hc", "uc", false);
		db.put("empty/string", std::string{}, false);
		db.put("empty/array", common::BinaryArray{}, false);
		std::string empty_string = "sentinel";
		common::BinaryArray empty_array{1};
		invariant(db.get("empty/string", empty_string) && empty_string.empty(),
		    "sqlite get confused a present empty string with a missing key");
		invariant(db.get("empty/array", empty_array) && empty_array.empty(),
		    "sqlite get confused a present empty byte array with a missing key");
		size_t empty_cursor_values = 0;
		for (auto cur = db.begin("empty/"); !cur.end(); cur.next()) {
			invariant(cur.get_value_string().empty() && cur.get_value_array().empty(),
			    "sqlite cursor did not preserve a present empty value");
			++empty_cursor_values;
		}
		invariant(empty_cursor_values == 2, "sqlite cursor omitted a present empty value");

		db.put("history/ha", "uaa", false);
		try {
			db.put("history/ha", "uab", true);
			std::cout << "value erroneously overwritten" << std::endl;
		} catch (...) {
		}
		db.del("history/hd", false);
		try {
			db.del("history/hd", true);
			std::cout << "value erroneously deleted" << std::endl;
		} catch (...) {
		}
		res = db.get("history/ha", str);
		std::cout << "res=" << res << std::endl;

		db.put("unspent/ua", "ua", false);
		db.put("unspent/ub", "ub", false);
		db.put("unspent/uc", "uc", false);
		db.commit_db_txn();
		backup_db("temp_db", "temp_db_backup");
		{
			DBsqliteKV backup(platform::O_READ_EXISTING, "temp_db_backup");
			std::string backup_value;
			invariant(backup.get("history/ha", backup_value) && backup_value == "uaa",
			    "sqlite online backup lost or changed a committed value");
			invariant(backup.get("unspent/uc", backup_value) && backup_value == "uc",
			    "sqlite online backup omitted a committed value");
		}
		bool rejected_existing_destination = false;
		try {
			backup_db("temp_db", "temp_db_backup");
		} catch (const platform::sqlite::Error &) {
			rejected_existing_destination = true;
		}
		invariant(rejected_existing_destination, "sqlite backup overwrote an existing destination");

		std::cout << "-- all keys forward --" << std::endl;
		for (auto cur = db.begin(std::string{}); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- all keys backward --" << std::endl;
		for (auto cur = db.rbegin(std::string{}); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- history forward --" << std::endl;
		for (auto cur = db.begin("history/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- history backward --" << std::endl;
		for (auto cur = db.rbegin("history/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- unspent forward --" << std::endl;
		for (auto cur = db.begin("unspent/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- unspent backward --" << std::endl;
		for (auto cur = db.rbegin("unspent/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- alpha forward --" << std::endl;
		for (auto cur = db.begin("alpha/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- alpha backward --" << std::endl;
		for (auto cur = db.rbegin("alpha/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- zero forward --" << std::endl;
		for (auto cur = db.begin("zero/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- zero backward --" << std::endl;
		for (auto cur = db.rbegin("zero/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		int c = 0;
		std::cout << "-- deleting c=2 iterating forward --" << std::endl;
		for (auto cur = db.begin(std::string{}); !cur.end(); ++c) {
			if (c == 2) {
				std::cout << "deleting " << cur.get_suffix() << std::endl;
				cur.erase();
			} else {
				std::cout << cur.get_suffix() << std::endl;
				cur.next();
			}
		}
		std::cout << "-- all keys forward --" << std::endl;
		for (auto cur = db.begin(std::string{}); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		c = 0;
		std::cout << "-- deleting c=2 iterating backward --" << std::endl;
		for (auto cur = db.rbegin(std::string{}); !cur.end(); ++c) {
			if (c == 2) {
				std::cout << "deleting " << cur.get_suffix() << std::endl;
				cur.erase();
			} else {
				std::cout << cur.get_suffix() << std::endl;
				cur.next();
			}
		}
		std::cout << "-- all keys forward --" << std::endl;
		for (auto cur = db.begin(std::string{}); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
	}
	delete_db("temp_db");
	delete_db("temp_db_backup");
}
