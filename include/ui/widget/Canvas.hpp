#pragma once

#include "ui/widget/Color.hpp"
#include "ui/widget/LayoutRect.hpp"
#include <vector>
#include <string>
#include <string_view>

namespace montauk::ui::widget {

// A single cell on the terminal grid.
struct Cell {
    std::string content = " "; // UTF-8 grapheme (usually 1-4 bytes)
    Style style;

    bool operator==(const Cell& other) const {
        return content == other.content && style == other.style;
    }

    bool operator!=(const Cell& other) const {
        return !(*this == other);
    }
};

// A 2D grid of Cells representing a rendering surface.
// Origin (0,0) is top-left. All write operations clip silently at bounds.
class Canvas {
public:
    Canvas(int width, int height);

    int width() const { return width_; }
    int height() const { return height_; }

    // Direct access (O(1)). Out-of-bounds reads/writes return a static dummy.
    Cell& at(int x, int y);
    const Cell& at(int x, int y) const;

    // Drawing primitives
    void clear(const Cell& fill_cell = Cell{" ", {}});
    void put(int x, int y, const std::string& grapheme, Style style = {});

    // Draw UTF-8 text starting at (x, y). Parses embedded ANSI SGR escapes
    // (30-37, 90-97, 38;2;R;G;B, 48;2;R;G;B, 0=reset, 1=bold, 2=dim, 4=underline).
    // Returns the x-coordinate after the last character drawn.
    int draw_text(int x, int y, std::string_view text, Style style = {});

    // Draw a bordered rectangle using Unicode box-drawing chars.
    void draw_rect(int x, int y, int w, int h, Style style = {});

    // Fill a rectangle with a cell value.
    void fill_rect(int x, int y, int w, int h, const Cell& cell);

    // Blit (copy) another canvas onto this one.
    void blit(const Canvas& source, int dest_x, int dest_y);
    void blit(const Canvas& source, int dest_x, int dest_y, int src_x, int src_y, int w, int h);

    // Resize the canvas (clears content).
    void resize(int width, int height);

    // Queue a graphics-protocol escape sequence to be emitted at frame flush,
    // with the cursor positioned at cell_rect's top-left. Cells inside
    // cell_rect are marked image-occupied — subsequent draw_text/put/draw_rect
    // calls that land in those cells become no-ops so they can't overwrite
    // the image.
    void paint_image(const LayoutRect& cell_rect, std::string escape_bytes);

    // Queue a graphics escape with no associated cell rect — the escape is
    // appended to the graphics-command stream but no cells are marked
    // image-occupied, so text underneath still renders. Use for delete /
    // cleanup commands where the point is to REMOVE an image and let text
    // show through.
    void push_graphics_command(std::string escape_bytes);

    // Pending graphics commands to be flushed after the cell-grid pass.
    struct GraphicsCommand {
        LayoutRect cell_rect;
        std::string escape;
    };
    const std::vector<GraphicsCommand>& graphics_commands() const { return graphics_; }

    // Whether a specific cell is covered by a queued image.
    bool is_image_occupied(int x, int y) const;

private:
    int width_ = 0;
    int height_ = 0;
    std::vector<Cell> buffer_;
    std::vector<uint8_t> image_mask_;  // width*height bytes, 0 = free, 1 = image-occupied
    std::vector<GraphicsCommand> graphics_;

    bool is_in_bounds(int x, int y) const {
        return x >= 0 && y >= 0 && x < width_ && y < height_;
    }
};

// Parse a SGR escape sequence (e.g. "\x1b[38;2;56;56;56m" or "\x1b[33m") into a
// Style. Recognizes the same codes as Canvas::draw_text. Used to bridge
// montauk's existing SGR-string config values into cell-based Style.
Style parse_sgr_style(std::string_view sgr);

} // namespace montauk::ui::widget
