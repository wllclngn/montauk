#pragma once

#include "ui/widget/Component.hpp"
#include "ui/widgets/ChartPanel.hpp"
#include "ui/widgets/SystemPanel.hpp"
#include "app/ChartHistories.hpp"

namespace montauk::ui::widgets {

// Owns the entire right column: 8 pixel-rendered ChartPanel widgets stacked
// vertically (PROCESSOR, GPU UTIL, VRAM, GPU MEM, ENC, DEC, MEMORY, NETWORK)
// and the SystemPanel for SYSTEM-focus mode. Switches between the two views
// based on the system_focus toggle.
//
// Holds visibility state internally; Renderer calls setters on key events.
// Persistent across frames so each ChartPanel can keep its scroll buffer
// and Kitty image ID alive.
class RightColumn : public widget::Component {
 public:
  RightColumn();

  // Visibility toggles. Renderer flips these from input handlers.
  void set_show_gpumon (bool on) { show_gpumon_  = on; }
  void set_show_thermal(bool on) { show_thermal_ = on; system_panel_.set_show_thermal(on); }
  void set_system_focus(bool on) { system_focus_ = on; }

  [[nodiscard]] bool show_gpumon () const { return show_gpumon_; }
  [[nodiscard]] bool show_thermal() const { return show_thermal_; }
  [[nodiscard]] bool system_focus() const { return system_focus_; }

  // Reset all toggles to defaults (gpumon + thermal on, system-focus off).
  // Mirrors what Renderer used to do on the 'R' keybind.
  void reset();

  void render(widget::Canvas& canvas,
              const widget::LayoutRect& rect,
              const montauk::model::Snapshot& snap) override;

 private:
  // Chart panels. Each binds to one history buffer in chart_histories().
  ChartPanel cpu_chart_      {"PROCESSOR", "cpu",     &montauk::app::chart_histories().cpu_total};
  ChartPanel gpu_util_chart_ {"GPU",       "gpu",     &montauk::app::chart_histories().gpu_util};
  ChartPanel vram_chart_     {"VRAM",      "gpu",     &montauk::app::chart_histories().vram_used};
  ChartPanel gpu_mem_chart_  {"MEM",       "gpu",     &montauk::app::chart_histories().gpu_mem};
  ChartPanel enc_chart_      {"ENC",       "gpu",     &montauk::app::chart_histories().enc};
  ChartPanel dec_chart_      {"DEC",       "gpu",     &montauk::app::chart_histories().dec};
  ChartPanel mem_chart_      {"MEMORY",    "memory",  &montauk::app::chart_histories().mem_used};
  ChartPanel net_chart_      {"NETWORK",   "network",
                              ChartPanel::DualCurveSources{
                                  &montauk::app::chart_histories().net_rx,
                                  &montauk::app::chart_histories().net_tx}};

  SystemPanel system_panel_{};

  bool show_gpumon_  = true;
  bool show_thermal_ = true;
  bool system_focus_ = false;
};

} // namespace montauk::ui::widgets
