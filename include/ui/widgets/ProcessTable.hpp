#pragma once

#include "ui/widget/Component.hpp"
#include <string>

namespace montauk::ui {
enum class SortMode { CPU, MEM, PID, NAME, GPU, GMEM };
}

namespace montauk::ui::widgets {

// PROCESS MONITOR. Owns all process-table state (sort mode, scroll offset,
// search filter, sticky column widths, CPU/GPU scaling preference). Input
// goes through Component::handle_input.
class ProcessTable : public widget::Component {
 public:
  enum class CPUScale { Total, Core };
  enum class GPUScale { Capacity, Utilization };

  ProcessTable() = default;

  void render(widget::Canvas& canvas,
              const widget::LayoutRect& rect,
              const montauk::model::Snapshot& snap) override;

  void handle_input(const widget::InputEvent& event) override;

  // Drop transient state back to defaults — bound to the 'R' reset keybind.
  void reset_view();

  // Used by main.cpp on startup to seed the scale modes from config.
  void set_cpu_scale(CPUScale s) { cpu_scale_ = s; }
  void set_gpu_scale(GPUScale s) { gpu_scale_ = s; }

  [[nodiscard]] bool search_mode() const { return search_mode_; }

 private:
  // Display state.
  SortMode sort_mode_   = SortMode::CPU;
  int      scroll_      = 0;
  CPUScale cpu_scale_   = CPUScale::Total;
  GPUScale gpu_scale_   = GPUScale::Utilization;
  bool     show_gmem_   = true;

  // Search overlay state.
  bool        search_mode_  = false;
  std::string filter_query_;

  // Pagination bookkeeping (computed each frame, used by scroll keys).
  int last_total_     = 0;
  int last_page_rows_ = 14;

  // Sticky column widths — only grow, never shrink. Keeps text from
  // visibly twitching as values fluctuate.
  int col_pid_w_       = 5;
  int col_user_w_      = 4;
  int col_gpu_digit_w_ = 4;
  int col_mem_w_       = 5;
  int col_gmem_w_      = 5;
};

} // namespace montauk::ui::widgets
