#pragma once

#include "ui/widget/Component.hpp"

namespace montauk::ui::widgets {

// PROCESS MONITOR widget. Owns the full process-table rendering including
// sort dispatch, search filtering, pagination, column-width management,
// per-row severity coloring, NFA-based command classification, and the
// optional search bar overlay. Its own Component subclass (not a generic
// Panel) because it has state and a custom shape (search bar modifies the
// bottom border).
//
// target_rows is the total rows allotted to this widget; the widget sizes
// itself (and reserves 2 rows for the search bar when active) to fill that
// row budget.
class ProcessTable : public widget::Component {
public:
  explicit ProcessTable(int target_rows) : target_rows_(target_rows) {}

  void render(widget::Canvas& canvas,
              const widget::LayoutRect& rect,
              const montauk::model::Snapshot& snap) override;

private:
  int target_rows_;
};

} // namespace montauk::ui::widgets
