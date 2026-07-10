// Unit test for the write-only JSON serializer (include/util/json.h).
// Builds a nested doc exercising escaping, numbers, nesting and comma placement,
// asserts the exact bytes, and emits the doc to stdout for an external json.tool pass.
#include "util/sink.h"
#include "util/json.h"
#include <stdio.h>
#include <string.h>

int main(void) {
  montauk_sink s; montauk_sink_init(&s, -1);   // fd -1: never drains, buffer holds it
  montauk_json j; montauk_json_init(&j, &s);

  montauk_json_obj_begin(&j);
    montauk_json_kstr(&j, "name", "futex");
    montauk_json_ku64(&j, "events", 42u);
    montauk_json_knum(&j, "p99_us", 8.3);
    montauk_json_kbool(&j, "ok", 1);
    montauk_json_key(&j, "verdict"); montauk_json_str(&j, "3 threads \"blocked\"\ttab\nnl");
    montauk_json_key(&j, "offenders"); montauk_json_arr_begin(&j);
      montauk_json_obj_begin(&j); montauk_json_ku64(&j, "tid", 1000u); montauk_json_kstr(&j, "comm", "worker.A"); montauk_json_obj_end(&j);
      montauk_json_obj_begin(&j); montauk_json_ku64(&j, "tid", 1001u); montauk_json_kstr(&j, "comm", "worker.B"); montauk_json_obj_end(&j);
    montauk_json_arr_end(&j);
    montauk_json_key(&j, "empty"); montauk_json_arr_begin(&j); montauk_json_arr_end(&j);
  montauk_json_obj_end(&j);

  const char* exp =
    "{\"name\":\"futex\",\"events\":42,\"p99_us\":8.3,\"ok\":true,"
    "\"verdict\":\"3 threads \\\"blocked\\\"\\ttab\\nnl\","
    "\"offenders\":[{\"tid\":1000,\"comm\":\"worker.A\"},{\"tid\":1001,\"comm\":\"worker.B\"}],"
    "\"empty\":[]}";

  int ok = (s.len == strlen(exp)) && (memcmp(s.data, exp, s.len) == 0);
  fprintf(stderr, ok ? "test_json: PASS\n" : "test_json: FAIL\n");
  if (!ok) fprintf(stderr, " got: %.*s\n exp: %s\n", (int)s.len, s.data, exp);
  fwrite(s.data, 1, s.len, stdout);   // for python -m json.tool
  return ok ? 0 : 1;
}
