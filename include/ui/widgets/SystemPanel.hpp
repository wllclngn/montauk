#pragma once

#include "ui/widget/Component.hpp"

namespace montauk::ui::widgets {

// SYSTEM-focus detail panel. Composes the dense info block (identity,
// runtime, CPU, GPU, memory, disk, network, thermal, security) and renders
// it as a single bordered widget::Panel filling the assigned rect.
//
// Stateless aside from the show_thermal toggle. Section builders live in
// the .cpp's anonymous namespace -- they are pure Row producers, not
// widgets in their own right.
class SystemPanel : public widget::Component {
 public:
  void set_show_thermal(bool on) { show_thermal_ = on; }
  [[nodiscard]] bool show_thermal() const { return show_thermal_; }

  void render(widget::Canvas& canvas,
              const widget::LayoutRect& rect,
              const montauk::model::Snapshot& snap) override;

 private:
  bool show_thermal_ = true;
};

} // namespace montauk::ui::widgets
