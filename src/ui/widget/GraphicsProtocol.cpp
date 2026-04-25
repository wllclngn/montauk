#include "ui/widget/GraphicsProtocol.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sstream>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace montauk::ui::widget {

namespace {

// Base64 encode a raw byte buffer. No line wrapping.
constexpr char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Attempt to read bytes from stdin for up to `timeout_ms` milliseconds.
// Used to collect terminal responses to CSI/OSC queries.
std::string read_with_timeout(int timeout_ms) {
  std::string out;
  char buf[256];
  auto remaining = [start = -1, timeout_ms]() mutable -> int {
    if (start < 0) start = 0;
    return timeout_ms;
  };
  pollfd pfd{STDIN_FILENO, POLLIN, 0};
  // Poll up to `timeout_ms`, draining whatever is available.
  for (;;) {
    pfd.revents = 0;
    int rc = ::poll(&pfd, 1, timeout_ms);
    if (rc <= 0) break;
    if (!(pfd.revents & POLLIN)) break;
    ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
    if (n <= 0) break;
    out.append(buf, buf + n);
    // Keep draining quickly; shorter timeout for follow-up bytes.
    timeout_ms = 20;
    (void)remaining;
  }
  return out;
}

// Temporarily set stdin to raw mode so we can read bytes without waiting
// for a newline. Restores previous termios on destruction.
class RawStdin {
 public:
  RawStdin() {
    if (!isatty(STDIN_FILENO)) { active_ = false; return; }
    if (tcgetattr(STDIN_FILENO, &saved_) != 0) { active_ = false; return; }
    termios raw = saved_;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN]  = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) { active_ = false; return; }
    active_ = true;
  }
  ~RawStdin() {
    if (active_) tcsetattr(STDIN_FILENO, TCSANOW, &saved_);
  }
  bool active() const { return active_; }
 private:
  termios saved_{};
  bool active_ = false;
};

// Write a raw string to stdout, ignoring short writes.
void write_all(const char* data, size_t len) {
  size_t done = 0;
  while (done < len) {
    ssize_t n = ::write(STDOUT_FILENO, data + done, len - done);
    if (n <= 0) break;
    done += static_cast<size_t>(n);
  }
}

} // namespace

// Base64 forward declaration — defined below at namespace scope.
std::string base64_encode(const uint8_t* data, size_t len);

namespace {

// Writes RGBA bytes to a unique file in /dev/shm (RAM-backed tmpfs) and
// returns the base64-encoded *path* — what Kitty's t=t transmission expects.
// Kitty reads the pixels from the file and (per spec) unlinks the file after
// reading. We also sweep files older than 500 ms on every call as a safety
// net in case a terminal misbehaves.
//
// This is the mechanism that replaces streaming ~300 KB of base64 through
// the PTY per chart per emit with a ~40-byte file-path escape. OUROBOROS
// uses the same approach for album art.
std::string write_rgba_to_shm_b64_path(const uint8_t* data, size_t len) {
  using clock = std::chrono::steady_clock;
  static std::vector<std::pair<std::string, clock::time_point>> pending;
  const auto now = clock::now();
  const auto cutoff = now - std::chrono::milliseconds(500);
  for (auto it = pending.begin(); it != pending.end();) {
    if (it->second < cutoff) {
      ::unlink(it->first.c_str());
      it = pending.erase(it);
    } else {
      ++it;
    }
  }

  char path_tpl[] = "/dev/shm/montauk-chart-XXXXXX";
  int fd = ::mkstemp(path_tpl);
  if (fd < 0) return {};

  size_t done = 0;
  while (done < len) {
    ssize_t n = ::write(fd, data + done, len - done);
    if (n <= 0) {
      ::close(fd);
      ::unlink(path_tpl);
      return {};
    }
    done += static_cast<size_t>(n);
  }
  ::close(fd);

  pending.emplace_back(std::string(path_tpl), clock::now());
  return base64_encode(reinterpret_cast<const uint8_t*>(path_tpl),
                       std::strlen(path_tpl));
}

} // namespace

std::string base64_encode(const uint8_t* data, size_t len) {
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  size_t i = 0;
  while (i + 3 <= len) {
    uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i+1]) << 8) | uint32_t(data[i+2]);
    out += kB64[(v >> 18) & 0x3F];
    out += kB64[(v >> 12) & 0x3F];
    out += kB64[(v >>  6) & 0x3F];
    out += kB64[ v        & 0x3F];
    i += 3;
  }
  if (i < len) {
    uint32_t v = uint32_t(data[i]) << 16;
    if (i + 1 < len) v |= uint32_t(data[i+1]) << 8;
    out += kB64[(v >> 18) & 0x3F];
    out += kB64[(v >> 12) & 0x3F];
    if (i + 1 < len) {
      out += kB64[(v >> 6) & 0x3F];
      out += '=';
    } else {
      out += "==";
    }
  }
  return out;
}

GraphicsEmitter& GraphicsEmitter::instance() {
  static GraphicsEmitter inst;
  return inst;
}

GraphicsEmitter::GraphicsEmitter() {
  detect();
}

void GraphicsEmitter::detect_cell_size() {
  // Primary: CSI 16 t → "\x1b[6;<h>;<w>t"
  {
    RawStdin raw;
    if (raw.active()) {
      const char* query = "\x1b[16t";
      write_all(query, std::strlen(query));
      std::string resp = read_with_timeout(80);
      // Response format: CSI 6 ; <h> ; <w> t
      auto p = resp.find("\x1b[6;");
      if (p != std::string::npos) {
        int h = 0, w = 0;
        if (std::sscanf(resp.c_str() + p, "\x1b[6;%d;%dt", &h, &w) == 2
            && h > 0 && w > 0) {
          cell_.h = h;
          cell_.w = w;
          return;
        }
      }
    }
  }

  // Secondary: TIOCGWINSZ ws_xpixel / ws_ypixel (often zero on modern kernels)
  winsize ws{};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0
      && ws.ws_xpixel > 0 && ws.ws_ypixel > 0
      && ws.ws_col > 0 && ws.ws_row > 0) {
    cell_.w = ws.ws_xpixel / ws.ws_col;
    cell_.h = ws.ws_ypixel / ws.ws_row;
    if (cell_.w > 0 && cell_.h > 0) return;
  }

  // Final fallback
  cell_.w = 8;
  cell_.h = 16;
}

void GraphicsEmitter::detect() {
  detect_cell_size();

  // Primary: Kitty graphics probe. Transmit a tiny 1x1 RGBA image with
  // action=query (a=q). Compliant terminals reply with "\x1b_Gi=<id>;OK\x1b\\".
  // Non-compliant terminals respond to nothing graphics-related but may echo.
  // We also pair it with CSI c DA1 so we always get *some* response, letting
  // us timeout-less detect Kitty's absence.
  {
    RawStdin raw;
    if (raw.active()) {
      // 1x1 RGBA pixel = 4 bytes = 8 base64 chars
      uint8_t px[4] = {0, 0, 0, 0};
      std::string b64 = base64_encode(px, 4);
      std::ostringstream probe;
      probe << "\x1b_Gi=9999,a=q,s=1,v=1,f=32;" << b64 << "\x1b\\"
            << "\x1b[c";  // CSI c DA1 — always answered
      write_all(probe.str().data(), probe.str().size());
      std::string resp = read_with_timeout(100);

      // Kitty OK response contains "Gi=9999;OK"
      if (resp.find("Gi=9999;OK") != std::string::npos
          || resp.find("_Gi=9999;OK") != std::string::npos) {
        protocol_ = Protocol::Kitty;
        return;
      }
      // Check Sixel support via DA1: response is "\x1b[?...c", and Sixel
      // capability is advertised as ";4;" in the parameter list.
      if (resp.find(";4;") != std::string::npos
          || resp.find(";4c") != std::string::npos) {
        protocol_ = Protocol::Sixel;
        return;
      }
    }
  }

  protocol_ = Protocol::None;
}

// Emit a full RGBA image.
//
// For Kitty: transmit via t=t (read-from-file). The image bytes are written
// to a RAM-backed /dev/shm tempfile and only the base64-encoded path crosses
// the PTY. This is required — streaming full base64 RGBA per chart per
// frame (~300 KB × 8 charts) was saturating the PTY buffer and blocking
// the render loop's write(), which starved input polling. Same mechanism
// OUROBOROS uses for album art.
//
// For Sixel: no tempfile path exists in the protocol, so we emit the full
// palette-reduced image inline. Sixel terminals are rarer and Sixel output
// is already much smaller than RGBA base64.
std::string GraphicsEmitter::emit_full(uint32_t chart_id,
                                        int cell_x, int cell_y,
                                        int cell_w, int cell_h,
                                        const uint8_t* rgba,
                                        int w_px, int h_px) {
  if (protocol_ == Protocol::None || rgba == nullptr || w_px <= 0 || h_px <= 0) {
    return {};
  }

  std::ostringstream oss;
  // Cursor to (cell_y+1, cell_x+1) — 1-based.
  oss << "\x1b[" << (cell_y + 1) << ';' << (cell_x + 1) << 'H';

  if (protocol_ == Protocol::Kitty) {
    // a=T transmit+display, t=t read RGBA bytes from the /dev/shm file whose
    // base64-encoded path follows the ';'. s/v = source pixel dims;
    // c/r = terminal cell anchor (required for correct placement, without
    // these Kitty can misplace or scroll the image). C=1 keeps the cursor
    // put. i=chart_id — successive emits with the same ID replace the
    // placement in place, which is what makes the chart "update" without
    // flicker. q=2 suppresses OK/error responses.
    const size_t bytes = static_cast<size_t>(w_px) * static_cast<size_t>(h_px) * 4;
    std::string b64_path = write_rgba_to_shm_b64_path(rgba, bytes);
    if (b64_path.empty()) return {};

    oss << "\x1b_Ga=T,t=t,i=" << chart_id
        << ",f=32,s=" << w_px << ",v=" << h_px
        << ",c=" << cell_w << ",r=" << cell_h
        << ",C=1,q=2;" << b64_path << "\x1b\\";
  } else if (protocol_ == Protocol::Sixel) {
    // Sixel: convert RGBA to Sixel (palette-reduced). Minimal implementation
    // — median-cut would be ideal but we use a simple 6x6x6 color cube as a
    // first pass. Each sixel band is 6 pixel rows tall.
    // Note: Sixel output is bandwidth-heavy; this path re-emits every frame.
    oss << "\x1bP0;0;0q";  // Sixel introducer, 0 aspect, 0 background
    oss << "\"1;1;" << w_px << ';' << h_px;

    // 6x6x6 color cube = 216 palette entries.
    for (int r = 0; r < 6; ++r) {
      for (int g = 0; g < 6; ++g) {
        for (int b = 0; b < 6; ++b) {
          int idx = r * 36 + g * 6 + b;
          int R = (r * 100) / 5, G = (g * 100) / 5, B = (b * 100) / 5;
          oss << '#' << idx << ";2;" << R << ';' << G << ';' << B;
        }
      }
    }

    // For each 6-row band, emit per-color runs.
    for (int band_y = 0; band_y < h_px; band_y += 6) {
      int band_h = std::min(6, h_px - band_y);
      for (int p = 0; p < 216; ++p) {
        int r_target = (p / 36) * 255 / 5;
        int g_target = ((p / 6) % 6) * 255 / 5;
        int b_target = (p % 6) * 255 / 5;
        bool any = false;
        std::string row;
        row.reserve(static_cast<size_t>(w_px));
        for (int x = 0; x < w_px; ++x) {
          uint8_t sixel_bits = 0;
          for (int dy = 0; dy < band_h; ++dy) {
            const uint8_t* px = rgba + ((band_y + dy) * w_px + x) * 4;
            int pr = (px[0] + 25) / 51;  // 0..5
            int pg = (px[1] + 25) / 51;
            int pb = (px[2] + 25) / 51;
            int qidx = pr * 36 + pg * 6 + pb;
            (void)r_target; (void)g_target; (void)b_target;
            if (qidx == p) sixel_bits |= (1u << dy);
          }
          if (sixel_bits) any = true;
          row += static_cast<char>('?' + sixel_bits);
        }
        if (any) {
          oss << '#' << p << row << '$';
        }
      }
      oss << '-';
    }
    oss << "\x1b\\";
  }

  return oss.str();
}

// Kitty a=d,d=i deletes the image (and all its placements) matching
// i=<chart_id>. Uppercase 'd=I' would also free the uploaded pixel
// data, which would force a full upload on re-show; we use lowercase
// 'd=i' so only placements are dropped and the data can still be
// re-placed later without re-transmitting. q=2 quiet.
std::string GraphicsEmitter::emit_delete(uint32_t chart_id) {
  if (protocol_ != Protocol::Kitty) return {};
  std::ostringstream oss;
  oss << "\x1b_Ga=d,d=i,i=" << chart_id << ",q=2\x1b\\";
  return oss.str();
}

} // namespace montauk::ui::widget
