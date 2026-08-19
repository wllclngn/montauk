// Case-fold table source for sublimation/src/text/case_fold_table.h.
//
// Emits (codepoint, towlower, towupper) for the whole range under the ambient
// UTF-8 locale. The table generator groups codepoints by the PAIR -- two
// characters fold together only when BOTH mappings agree, which is grep's own
// rule and the only one that matches it. Deriving from glibc rather than from
// Python matters: the two disagree in both directions.
//
//   cc -O2 -o genfold sublimation/tools/genfold.c && ./genfold > lu.txt
//
// then group by (lower, upper), drop classes whose two UTF-8 encodings differ
// only in the last byte into sub_fold_table, and the rest into
// sub_fold_alt_table.

#include <stdio.h>
#include <wctype.h>
#include <locale.h>
int main(void) {
  if (!setlocale(LC_ALL, "")) return 1;
  for (wint_t c = 1; c < 0x110000; c++)
    printf("%u %u %u\n", (unsigned)c, (unsigned)towlower(c), (unsigned)towupper(c));
  return 0;
}
