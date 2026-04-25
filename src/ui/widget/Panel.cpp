#include "ui/widget/Panel.hpp"
#include "ui/Config.hpp"

#include <algorithm>

namespace montauk::ui::widget {

namespace {

// Visual column width of a UTF-8 / ANSI-bearing string. Strips CSI escape
// sequences (ESC [ ... letter) and counts UTF-8 leading bytes — non-ASCII
// graphemes are assumed single-cell, which is correct for everything
// montauk emits (no CJK, no emoji in panel values).
int visual_cols(std::string_view s) {
  int cols = 0;
  for (size_t i = 0; i < s.size();) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    if (c == 0x1B && i + 1 < s.size() && s[i + 1] == '[') {
      // CSI: skip until terminator (alphabetic byte 0x40-0x7E)
      i += 2;
      while (i < s.size()) {
        unsigned char x = static_cast<unsigned char>(s[i]);
        ++i;
        if (x >= 0x40 && x <= 0x7E) break;
      }
      continue;
    }
    if ((c & 0xC0) == 0x80) { ++i; continue; }  // UTF-8 continuation
    ++cols;
    ++i;
  }
  return cols;
}

// Style for a row's value column based on severity.
Style severity_style(int severity) {
  const auto& uic = ui_config();
  if (severity >= 2) return parse_sgr_style(uic.warning);
  if (severity >= 1) return parse_sgr_style(uic.caution);
  return Style{};  // default fg
}

} // namespace

void Panel::render(Canvas& canvas,
                   const LayoutRect& rect,
                   const montauk::model::Snapshot& /*snap*/) {
  const auto& uic = ui_config();
  Style border_style = parse_sgr_style(uic.border);
  Style title_style  = parse_sgr_style(uic.accent);
  LayoutRect inner = draw_box_border(canvas, rect, title_, border_style, title_style);
  if (inner.width <= 0 || inner.height <= 0) return;

  const Style muted_style = parse_sgr_style(uic.muted);

  for (size_t i = 0; i < rows_.size(); ++i) {
    if (static_cast<int>(i) >= inner.height) break;
    const Row& r = rows_[i];
    const int y = inner.y + static_cast<int>(i);

    switch (r.kind) {
      case Row::Kind::Empty:
        // Nothing to draw — Canvas was cleared to spaces by the caller.
        break;

      case Row::Kind::Header: {
        // Section header — drawn left-anchored. Severity-tinted only when
        // explicitly set; default reads as muted-bold-ish (we use accent
        // for callers that mark headers with severity 1+, otherwise default).
        Style s = (r.severity > 0) ? severity_style(r.severity) : Style{};
        canvas.draw_text(inner.x, y, r.label, s);
        break;
      }

      case Row::Kind::KeyValue: {
        // Label at the left, value right-anchored. Both placed at fixed
        // cell positions — no padding strings, so values stay visually
        // pinned to the right edge regardless of label length or panel
        // width changes.
        Style row_style = severity_style(r.severity);
        Style label_style = (r.severity > 0) ? row_style : muted_style;
        canvas.draw_text(inner.x, y, r.label, label_style);

        const int v_cols = visual_cols(r.value);
        int v_x = inner.x + inner.width - v_cols;
        // Don't let value overlap label if width is too tight.
        const int label_cols = visual_cols(r.label);
        if (v_x < inner.x + label_cols + 1) v_x = inner.x + label_cols + 1;
        if (v_x < inner.x) v_x = inner.x;
        canvas.draw_text(v_x, y, r.value, row_style);
        break;
      }
    }
  }
}

} // namespace montauk::ui::widget
