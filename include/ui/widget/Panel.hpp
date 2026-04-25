#pragma once

#include "ui/widget/Component.hpp"
#include <string>
#include <vector>

namespace montauk::ui::widget {

// One row of a montauk Panel. Three kinds:
//   Empty   — vertical spacer; nothing drawn.
//   Header  — single text line drawn left-anchored; meant for section titles
//             like "DISK I/O" or "NETWORK" inside the SYSTEM panel.
//   KeyValue — label drawn at the left, value drawn right-anchored to the
//             panel's inner-rect right edge. No string padding involved —
//             label and value are placed at independent cell positions, so
//             values stay visually pinned to the right edge under any width
//             change. severity 0 = normal, 1 = caution, 2 = warning.
struct Row {
  enum class Kind { Empty, Header, KeyValue };
  Kind kind = Kind::Empty;
  std::string label;   // Header text, or KeyValue label
  std::string value;   // KeyValue right-side text (may contain embedded SGR)
  int severity = 0;

  static Row empty() { return Row{Kind::Empty, {}, {}, 0}; }
  static Row header(std::string text, int sev = 0) { return Row{Kind::Header, std::move(text), {}, sev}; }
  static Row kv(std::string label, std::string value, int sev = 0) {
    return Row{Kind::KeyValue, std::move(label), std::move(value), sev};
  }
};

// Bordered panel. Title is centered on the top border in the accent color;
// rows are drawn cell-by-cell inside the inner rect — labels at the left
// edge, values right-anchored. Severity-driven row tinting happens at draw
// time, not via embedded SGR in the strings.
class Panel : public Component {
public:
  Panel(std::string title, std::vector<Row> rows)
      : title_(std::move(title)), rows_(std::move(rows)) {}

  // Total panel height (rows) for `content_rows` interior lines including
  // both border edges.
  [[nodiscard]] static int height_for(int content_rows) { return content_rows + 2; }

  void render(Canvas& canvas,
              const LayoutRect& rect,
              const montauk::model::Snapshot& snap) override;

private:
  std::string title_;
  std::vector<Row> rows_;
};

} // namespace montauk::ui::widget
