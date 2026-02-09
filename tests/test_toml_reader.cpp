#include "minitest.hpp"
#include "util/TomlReader.hpp"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

static std::string tmp_path(const char* suffix) {
  return std::string("/tmp/montauk_test_toml_") + suffix + ".toml";
}

static void write_file(const std::string& path, const std::string& content) {
  std::ofstream f(path);
  f << content;
}

static void remove_file(const std::string& path) {
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

TEST(toml_load_missing_file) {
  montauk::util::TomlReader tr;
  ASSERT_TRUE(!tr.load("/tmp/montauk_test_toml_nonexistent_file.toml"));
}

TEST(toml_load_basic) {
  auto path = tmp_path("basic");
  write_file(path,
    "[ui]\n"
    "alt_screen = true\n"
    "time_format = \"%H:%M\"\n"
    "\n"
    "[thresholds]\n"
    "proc_caution_pct = 60\n"
    "proc_warning_pct = 80\n"
  );
  montauk::util::TomlReader tr;
  ASSERT_TRUE(tr.load(path));
  ASSERT_EQ(tr.get_bool("ui", "alt_screen", false), true);
  ASSERT_EQ(tr.get_string("ui", "time_format"), "%H:%M");
  ASSERT_EQ(tr.get_int("thresholds", "proc_caution_pct"), 60);
  ASSERT_EQ(tr.get_int("thresholds", "proc_warning_pct"), 80);
  remove_file(path);
}

TEST(toml_defaults_for_missing_keys) {
  auto path = tmp_path("defaults");
  write_file(path, "[ui]\nalt_screen = true\n");
  montauk::util::TomlReader tr;
  ASSERT_TRUE(tr.load(path));
  ASSERT_EQ(tr.get_string("ui", "missing_key", "fallback"), "fallback");
  ASSERT_EQ(tr.get_int("ui", "missing_int", 42), 42);
  ASSERT_EQ(tr.get_bool("ui", "missing_bool", true), true);
  // Missing section entirely
  ASSERT_EQ(tr.get_string("nosection", "key", "nope"), "nope");
  ASSERT_EQ(tr.get_int("nosection", "key", -1), -1);
  remove_file(path);
}

TEST(toml_has) {
  auto path = tmp_path("has");
  write_file(path, "[roles]\naccent = 11\n");
  montauk::util::TomlReader tr;
  ASSERT_TRUE(tr.load(path));
  ASSERT_TRUE(tr.has("roles", "accent"));
  ASSERT_TRUE(!tr.has("roles", "missing"));
  ASSERT_TRUE(!tr.has("nosection", "accent"));
  remove_file(path);
}

TEST(toml_bool_variants) {
  auto path = tmp_path("bool");
  write_file(path,
    "[b]\n"
    "a = true\n"
    "b = True\n"
    "c = TRUE\n"
    "d = 1\n"
    "e = false\n"
    "f = False\n"
    "g = FALSE\n"
    "h = 0\n"
    "i = junk\n"
  );
  montauk::util::TomlReader tr;
  ASSERT_TRUE(tr.load(path));
  ASSERT_EQ(tr.get_bool("b", "a"), true);
  ASSERT_EQ(tr.get_bool("b", "b"), true);
  ASSERT_EQ(tr.get_bool("b", "c"), true);
  ASSERT_EQ(tr.get_bool("b", "d"), true);
  ASSERT_EQ(tr.get_bool("b", "e"), false);
  ASSERT_EQ(tr.get_bool("b", "f"), false);
  ASSERT_EQ(tr.get_bool("b", "g"), false);
  ASSERT_EQ(tr.get_bool("b", "h"), false);
  // "junk" -> returns default
  ASSERT_EQ(tr.get_bool("b", "i", true), true);
  ASSERT_EQ(tr.get_bool("b", "i", false), false);
  remove_file(path);
}

TEST(toml_int_coercion) {
  auto path = tmp_path("int");
  write_file(path,
    "[n]\n"
    "pos = 42\n"
    "neg = -7\n"
    "zero = 0\n"
    "str = hello\n"
  );
  montauk::util::TomlReader tr;
  ASSERT_TRUE(tr.load(path));
  ASSERT_EQ(tr.get_int("n", "pos"), 42);
  ASSERT_EQ(tr.get_int("n", "neg"), -7);
  ASSERT_EQ(tr.get_int("n", "zero"), 0);
  // non-numeric string returns default
  ASSERT_EQ(tr.get_int("n", "str", 99), 99);
  remove_file(path);
}

TEST(toml_quoted_strings) {
  auto path = tmp_path("quoted");
  write_file(path,
    "[s]\n"
    "plain = hello\n"
    "quoted = \"world\"\n"
    "empty = \"\"\n"
    "hex = \"#FF00AA\"\n"
  );
  montauk::util::TomlReader tr;
  ASSERT_TRUE(tr.load(path));
  ASSERT_EQ(tr.get_string("s", "plain"), "hello");
  ASSERT_EQ(tr.get_string("s", "quoted"), "world");
  ASSERT_EQ(tr.get_string("s", "empty"), "");
  ASSERT_EQ(tr.get_string("s", "hex"), "#FF00AA");
  remove_file(path);
}

TEST(toml_comments_and_whitespace) {
  auto path = tmp_path("comments");
  write_file(path,
    "# Top-level comment\n"
    "\n"
    "[ ui ]  \n"
    "  key1  =  val1  \n"
    "# inline section comment\n"
    "  key2 = 10\n"
  );
  montauk::util::TomlReader tr;
  ASSERT_TRUE(tr.load(path));
  ASSERT_EQ(tr.get_string("ui", "key1"), "val1");
  ASSERT_EQ(tr.get_int("ui", "key2"), 10);
  remove_file(path);
}

TEST(toml_set_and_overwrite) {
  montauk::util::TomlReader tr;
  tr.set("ui", "alt_screen", true);
  tr.set("ui", "fps", 60);
  tr.set("ui", "title", std::string("montauk"));
  ASSERT_EQ(tr.get_bool("ui", "alt_screen"), true);
  ASSERT_EQ(tr.get_int("ui", "fps"), 60);
  ASSERT_EQ(tr.get_string("ui", "title"), "montauk");
  // Overwrite
  tr.set("ui", "fps", 30);
  ASSERT_EQ(tr.get_int("ui", "fps"), 30);
}

TEST(toml_roundtrip) {
  auto path = tmp_path("roundtrip");
  montauk::util::TomlReader tr;
  tr.set("palette", "color0", std::string("#2E2E2E"));
  tr.set("palette", "color1", std::string("#CC0000"));
  tr.set("roles", "accent", 11);
  tr.set("ui", "alt_screen", true);
  tr.set("ui", "time_format", std::string("%H:%M:%S"));
  ASSERT_TRUE(tr.save(path));

  montauk::util::TomlReader tr2;
  ASSERT_TRUE(tr2.load(path));
  ASSERT_EQ(tr2.get_string("palette", "color0"), "#2E2E2E");
  ASSERT_EQ(tr2.get_string("palette", "color1"), "#CC0000");
  ASSERT_EQ(tr2.get_int("roles", "accent"), 11);
  ASSERT_EQ(tr2.get_bool("ui", "alt_screen"), true);
  ASSERT_EQ(tr2.get_string("ui", "time_format"), "%H:%M:%S");
  remove_file(path);
}

TEST(toml_global_keys_no_section) {
  auto path = tmp_path("global");
  write_file(path, "key = value\n[sec]\nother = 1\n");
  montauk::util::TomlReader tr;
  ASSERT_TRUE(tr.load(path));
  // Keys before any [section] go under empty-string section
  ASSERT_EQ(tr.get_string("", "key"), "value");
  ASSERT_EQ(tr.get_int("sec", "other"), 1);
  remove_file(path);
}
