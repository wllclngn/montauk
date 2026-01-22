#include "ui/Input.hpp"
#include "ui/Config.hpp"
#include "ui/Terminal.hpp"
#include <unistd.h>
#include <poll.h>
#include <algorithm>

namespace montauk::ui {

bool has_input_available(int timeout_ms) {
  struct pollfd pfd{.fd=STDIN_FILENO,.events=POLLIN,.revents=0};
  int to = timeout_ms; 
  if (to < 10) to = 10; 
  if (to > 1000) to = 1000;
  int rv = ::poll(&pfd, 1, to);
  return rv > 0 && (pfd.revents & POLLIN);
}

bool handle_keyboard_input(int /*sleep_ms_ref*/, bool& show_help) {
  unsigned char buf[8]; 
  ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
  if (n <= 0) return false;
  
  size_t k = 0;
  while (k < (size_t)n) {
    unsigned char c = buf[k++];
    if (c == 'q' || c == 'Q') { 
      return true; // quit
    }
    else if (c == 'h' || c == 'H') { show_help = !show_help; }
    else if (c == '+') { /* handled by caller */ }
    else if (c == '-') { /* handled by caller */ }
    else if (c == 'c' || c == 'C') { g_ui.sort = SortMode::CPU; }
    else if (c == 'm' || c == 'M') { g_ui.sort = SortMode::MEM; }
    else if (c == 'p' || c == 'P') { g_ui.sort = SortMode::PID; }
    else if (c == 'n' || c == 'N') { g_ui.sort = SortMode::NAME; }
    else if (c == 'G') { g_ui.show_gpumon = !g_ui.show_gpumon; }
    else if (c == 'v' || c == 'V') { g_ui.sort = SortMode::GMEM; }
    else if (c == 'g') { g_ui.sort = SortMode::GPU; }
    else if (c == 'i' || c == 'I') { 
      g_ui.cpu_scale = (g_ui.cpu_scale==UIState::CPUScale::Total? UIState::CPUScale::Core : UIState::CPUScale::Total); 
    }
    else if (c == 'u' || c == 'U') { 
      g_ui.gpu_scale = (g_ui.gpu_scale==UIState::GPUScale::Capacity? UIState::GPUScale::Utilization : UIState::GPUScale::Capacity); 
    }
    else if (c == 's' || c == 'S') {
      g_ui.system_focus = !g_ui.system_focus;
      if (g_ui.system_focus) {
        g_ui.show_gpumon = false;
        g_ui.show_disk = false;
        g_ui.show_net = false;
      } else {
        g_ui.show_gpumon = true;
        g_ui.show_disk = true;
        g_ui.show_net = true;
      }
    }
    else if (c == 'R') { reset_ui_defaults(); }
    else if (c == 't' || c == 'T') { g_ui.show_thermal = !g_ui.show_thermal; }
    else if (c == 'd' || c == 'D') { g_ui.show_disk = !g_ui.show_disk; }
    else if (c == 'N') { g_ui.show_net = !g_ui.show_net; }
    else if (c == 0x1B) {
      // ESC sequences
      unsigned char a=0,b=0, d=0;
      if (k < (size_t)n) a = buf[k++]; else break;
      if (a == '[') {
        if (k < (size_t)n) b = buf[k++]; else break;
        if (b >= 'A' && b <= 'D') {
          int max_scroll = std::max(0, g_ui.last_proc_total - g_ui.last_proc_page_rows);
          if (b=='A') { if (g_ui.scroll > 0) g_ui.scroll--; }
          else if (b=='B') { g_ui.scroll = std::min(g_ui.scroll + 1, max_scroll); }
        } else if (b=='5' || b=='6') {
          if (k < (size_t)n) d = buf[k++];
          if (d=='~') {
            int page = std::max(1, g_ui.last_proc_page_rows - 2);
            int max_scroll = std::max(0, g_ui.last_proc_total - g_ui.last_proc_page_rows);
            if (b=='5') { g_ui.scroll = std::max(0, g_ui.scroll - page); }
            else { g_ui.scroll = std::min(g_ui.scroll + page, max_scroll); }
          }
        }
      }
    }
  }
  return false;
}

} // namespace montauk::ui
