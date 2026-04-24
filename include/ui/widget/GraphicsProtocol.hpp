#pragma once

#include <cstdint>
#include <string>

namespace montauk::ui::widget {

// Terminal graphics protocol negotiation and emission.
//
// At startup, detect() probes the terminal for Kitty graphics (primary) then
// Sixel (secondary). The result is cached. SIGWINCH can call redetect().
//
// emit_full() builds the escape sequence to transmit+display a full RGBA
// image at cell (cell_x, cell_y) with the given chart_id. Used for the first
// frame and on resize.
//
// emit_column() builds the escape sequence to composite a 1-pixel-wide RGBA
// strip onto the rightmost column of a previously-transmitted image. This is
// the incremental-update path used on every subsequent frame on Kitty. On
// Sixel (no delta protocol) returns an empty string — caller re-emits full.
//
// Pixel coordinates for emit_column are in *image-local* pixels (relative to
// the image's upper-left corner), not terminal cells.

enum class Protocol : uint8_t {
  None  = 0,  // no graphics support detected
  Kitty = 1,
  Sixel = 2,
};

struct CellPixelSize {
  int w = 8;
  int h = 16;
};

class GraphicsEmitter {
 public:
  // Lazy-initialized singleton. First call runs detect().
  static GraphicsEmitter& instance();

  [[nodiscard]] Protocol protocol() const { return protocol_; }
  [[nodiscard]] CellPixelSize cell_size() const { return cell_; }

  // A human-readable label for the detected protocol. Used by the startup
  // diagnostic and by the "terminal lacks graphics" notice.
  [[nodiscard]] const char* protocol_name() const;

  // Build the escape sequence(s) to transmit+display a full RGBA image at
  // cell (cell_x, cell_y), occupying (cell_w, cell_h) terminal cells.
  // `chart_id` identifies this chart for later updates. Use on the first
  // frame and when the chart's cell footprint changes (creates a placement).
  // Empty string if no graphics support.
  [[nodiscard]] std::string emit_full(uint32_t chart_id,
                                       int cell_x, int cell_y,
                                       int cell_w, int cell_h,
                                       const uint8_t* rgba,
                                       int w_px, int h_px);

  // Kitty-only: replace the RGBA data for a previously-displayed image
  // without creating a new placement. The existing placement continues to
  // display at its original cell position, but now shows the new bytes.
  // Use on every frame after the initial emit_full to update the chart
  // in place without the "flash/disappear" that comes from re-transmitting
  // with a=T (which creates new placements and orphans old ones).
  // Returns empty on Sixel (Sixel has no image-data-replace semantics —
  // Sixel callers should use emit_full every frame).
  [[nodiscard]] std::string emit_replace(uint32_t chart_id,
                                          const uint8_t* rgba,
                                          int w_px, int h_px);

  // Kitty only: composite a 1-px-wide RGBA strip at (x_px, 0) onto the
  // previous frame of `chart_id`. `h_px` must match the chart height.
  // Returns empty string on Sixel or when protocol is None.
  [[nodiscard]] std::string emit_column(uint32_t chart_id,
                                         int x_px, int h_px,
                                         const uint8_t* rgba_column);

  // Kitty only: delete the image (and all its placements) identified by
  // `chart_id` from the terminal. Used when a chart transitions from
  // visible to hidden (e.g. SYSTEM-focus mode) so Kitty doesn't keep
  // rendering the stale placement over newly-drawn text. Returns empty
  // on non-Kitty protocols — Sixel leaves no placement to clean up.
  [[nodiscard]] std::string emit_delete(uint32_t chart_id);

  // Re-probe the terminal (on SIGWINCH). Cell size and protocol may change.
  void redetect();

 private:
  GraphicsEmitter();
  void detect();
  void detect_cell_size();

  Protocol protocol_ = Protocol::None;
  CellPixelSize cell_;
};

// Base64 encode a raw byte buffer into a string (no line wrapping). Exposed
// for testing and for any callers that need it.
[[nodiscard]] std::string base64_encode(const uint8_t* data, size_t len);

} // namespace montauk::ui::widget
