// Unit test for the write-only JSON serializer (sublimation_json.h).
// Builds a nested doc exercising escaping, numbers, nesting and comma placement,
// asserts the exact bytes, and emits the doc to stdout for an external json.tool pass.
#include "sublimation_sink.h"
#include "sublimation_json.h"
#include <stdio.h>
#include <string.h>

int main(void) {
  sublimation_sink s; sublimation_sink_init(&s, -1);   // fd -1: never drains, buffer holds it
  sublimation_json j; sublimation_json_init(&j, &s);

  sublimation_json_obj_begin(&j);
    sublimation_json_kstr(&j, "name", "futex");
    sublimation_json_ku64(&j, "events", 42u);
    sublimation_json_knum(&j, "p99_us", 8.3);
    sublimation_json_kbool(&j, "ok", 1);
    sublimation_json_key(&j, "verdict"); sublimation_json_str(&j, "3 threads \"blocked\"\ttab\nnl");
    sublimation_json_key(&j, "offenders"); sublimation_json_arr_begin(&j);
      sublimation_json_obj_begin(&j); sublimation_json_ku64(&j, "tid", 1000u); sublimation_json_kstr(&j, "comm", "worker.A"); sublimation_json_obj_end(&j);
      sublimation_json_obj_begin(&j); sublimation_json_ku64(&j, "tid", 1001u); sublimation_json_kstr(&j, "comm", "worker.B"); sublimation_json_obj_end(&j);
    sublimation_json_arr_end(&j);
    sublimation_json_key(&j, "empty"); sublimation_json_arr_begin(&j); sublimation_json_arr_end(&j);
  sublimation_json_obj_end(&j);

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
