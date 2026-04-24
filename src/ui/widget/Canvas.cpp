#include "ui/widget/Canvas.hpp"
#include <algorithm>
#include <wchar.h>

namespace montauk::ui::widget {

// Decode UTF-8 character to wchar_t, return bytes consumed (0 on error).
static int utf8_to_wchar(const char* s, size_t len, wchar_t* out) {
    if (len == 0 || !s) return 0;
    unsigned char c = static_cast<unsigned char>(s[0]);

    if ((c & 0x80) == 0) {
        *out = c;
        return 1;
    } else if ((c & 0xE0) == 0xC0 && len >= 2) {
        *out = ((c & 0x1F) << 6) | (s[1] & 0x3F);
        return 2;
    } else if ((c & 0xF0) == 0xE0 && len >= 3) {
        *out = ((c & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return 3;
    } else if ((c & 0xF8) == 0xF0 && len >= 4) {
        *out = ((c & 0x07) << 18) | ((s[1] & 0x3F) << 12) |
               ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return 4;
    }
    return 0;
}

Canvas::Canvas(int width, int height) : width_(width), height_(height) {
    buffer_.resize(static_cast<size_t>(width) * static_cast<size_t>(height));
    image_mask_.assign(static_cast<size_t>(width) * static_cast<size_t>(height), 0);
}

bool Canvas::is_image_occupied(int x, int y) const {
    if (!is_in_bounds(x, y)) return false;
    return image_mask_[static_cast<size_t>(y) * static_cast<size_t>(width_) + static_cast<size_t>(x)] != 0;
}

void Canvas::paint_image(const LayoutRect& cell_rect, std::string escape_bytes) {
    if (escape_bytes.empty()) return;
    graphics_.push_back({cell_rect, std::move(escape_bytes)});
    for (int y = cell_rect.y; y < cell_rect.y + cell_rect.height; ++y) {
        for (int x = cell_rect.x; x < cell_rect.x + cell_rect.width; ++x) {
            if (!is_in_bounds(x, y)) continue;
            image_mask_[static_cast<size_t>(y) * static_cast<size_t>(width_) + static_cast<size_t>(x)] = 1;
        }
    }
}

void Canvas::push_graphics_command(std::string escape_bytes) {
    if (escape_bytes.empty()) return;
    graphics_.push_back({LayoutRect{0, 0, 0, 0}, std::move(escape_bytes)});
}

Cell& Canvas::at(int x, int y) {
    if (!is_in_bounds(x, y)) {
        static Cell dummy;
        return dummy;
    }
    return buffer_[static_cast<size_t>(y) * static_cast<size_t>(width_) + static_cast<size_t>(x)];
}

const Cell& Canvas::at(int x, int y) const {
    if (!is_in_bounds(x, y)) {
        static Cell dummy;
        return dummy;
    }
    return buffer_[static_cast<size_t>(y) * static_cast<size_t>(width_) + static_cast<size_t>(x)];
}

void Canvas::clear(const Cell& fill_cell) {
    std::fill(buffer_.begin(), buffer_.end(), fill_cell);
}

void Canvas::put(int x, int y, const std::string& grapheme, Style style) {
    if (is_in_bounds(x, y) && !is_image_occupied(x, y)) {
        buffer_[static_cast<size_t>(y) * static_cast<size_t>(width_) + static_cast<size_t>(x)] = Cell{grapheme, style};
    }
}

void Canvas::resize(int width, int height) {
    if (width_ == width && height_ == height) return;
    width_ = width;
    height_ = height;
    buffer_.clear();
    buffer_.resize(static_cast<size_t>(width) * static_cast<size_t>(height));
    image_mask_.assign(static_cast<size_t>(width) * static_cast<size_t>(height), 0);
    graphics_.clear();
}

static size_t utf8_char_len(char c) {
    unsigned char uc = static_cast<unsigned char>(c);
    if ((uc & 0x80) == 0) return 1;
    if ((uc & 0xE0) == 0xC0) return 2;
    if ((uc & 0xF0) == 0xE0) return 3;
    if ((uc & 0xF8) == 0xF0) return 4;
    return 1; // Invalid or continuation; advance by 1
}

static int parse_int(const char*& p) {
    int v = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (*p - '0');
        p++;
    }
    return v;
}

int Canvas::draw_text(int x, int y, std::string_view text, Style initial_style) {
    if (y < 0 || y >= height_) return x;

    int current_x = x;
    Style current_style = initial_style;

    size_t i = 0;
    while (i < text.length()) {
        if (current_x >= width_) break;

        // ANSI SGR escape sequence: ESC [ params m
        if (text[i] == '\033' && i + 1 < text.length() && text[i+1] == '[') {
            const char* p = text.data() + i + 2; // Skip ESC [

            while (true) {
                int code = parse_int(p);

                switch (code) {
                    case 0: current_style = Style{}; break;
                    case 1: current_style.attr = current_style.attr | Attribute::Bold; break;
                    case 2: current_style.attr = current_style.attr | Attribute::Dim; break;
                    case 4: current_style.attr = current_style.attr | Attribute::Underline; break;
                    case 30: current_style.fg = Color::Black; break;
                    case 31: current_style.fg = Color::Red; break;
                    case 32: current_style.fg = Color::Green; break;
                    case 33: current_style.fg = Color::Yellow; break;
                    case 34: current_style.fg = Color::Blue; break;
                    case 35: current_style.fg = Color::Magenta; break;
                    case 36: current_style.fg = Color::Cyan; break;
                    case 37: current_style.fg = Color::White; break;
                    case 39: current_style.fg = Color::Default; break;
                    case 90: current_style.fg = Color::BrightBlack; break;
                    case 91: current_style.fg = Color::BrightRed; break;
                    case 92: current_style.fg = Color::BrightGreen; break;
                    case 93: current_style.fg = Color::BrightYellow; break;
                    case 94: current_style.fg = Color::BrightBlue; break;
                    case 95: current_style.fg = Color::BrightMagenta; break;
                    case 96: current_style.fg = Color::BrightCyan; break;
                    case 97: current_style.fg = Color::BrightWhite; break;
                    case 38: // Extended fg: 38;2;R;G;B (truecolor)
                        if (*p == ';') {
                            p++;
                            int mode = parse_int(p);
                            if (mode == 2 && *p == ';') {
                                p++; int r = parse_int(p);
                                if (*p == ';') { p++; int g = parse_int(p);
                                    if (*p == ';') { p++; int b = parse_int(p);
                                        current_style.fg = rgb_color(
                                            static_cast<uint8_t>(r),
                                            static_cast<uint8_t>(g),
                                            static_cast<uint8_t>(b));
                                    }
                                }
                            }
                        }
                        break;
                    case 48: // Extended bg: 48;2;R;G;B (truecolor)
                        if (*p == ';') {
                            p++;
                            int mode = parse_int(p);
                            if (mode == 2 && *p == ';') {
                                p++; int r = parse_int(p);
                                if (*p == ';') { p++; int g = parse_int(p);
                                    if (*p == ';') { p++; int b = parse_int(p);
                                        current_style.bg = rgb_color(
                                            static_cast<uint8_t>(r),
                                            static_cast<uint8_t>(g),
                                            static_cast<uint8_t>(b));
                                    }
                                }
                            }
                        }
                        break;
                    default: break;
                }

                if (*p == ';') {
                    p++;
                } else {
                    break;
                }
            }

            // Skip until 'm' or end
            while (*p && *p != 'm') p++;
            if (*p == 'm') p++;

            i = static_cast<size_t>(p - text.data());
            continue;
        }

        size_t len = utf8_char_len(text[i]);
        if (i + len > text.length()) break;

        std::string grapheme(text.substr(i, len));

        wchar_t wc = 0;
        int char_width = 1;
        if (utf8_to_wchar(text.data() + i, len, &wc) > 0) {
            int w = wcwidth(wc);
            if (w > 0) char_width = w;
        }

        if (current_x >= 0 && current_x < width_) {
            put(current_x, y, grapheme, current_style);

            // For double-width chars, mark the next cell as continuation
            if (char_width == 2 && current_x + 1 < width_) {
                put(current_x + 1, y, "", current_style);
            }
        }

        current_x += char_width;
        i += len;
    }
    return current_x;
}

void Canvas::draw_rect(int x, int y, int w, int h, Style style) {
    if (w <= 0 || h <= 0) return;

    // Corners
    put(x, y, "┌", style);
    put(x + w - 1, y, "┐", style);
    put(x, y + h - 1, "└", style);
    put(x + w - 1, y + h - 1, "┘", style);

    // Horizontal edges
    for (int i = 1; i < w - 1; ++i) {
        put(x + i, y, "─", style);
        put(x + i, y + h - 1, "─", style);
    }

    // Vertical edges
    for (int i = 1; i < h - 1; ++i) {
        put(x, y + i, "│", style);
        put(x + w - 1, y + i, "│", style);
    }
}

void Canvas::fill_rect(int x, int y, int w, int h, const Cell& cell) {
    for (int cy = y; cy < y + h; ++cy) {
        for (int cx = x; cx < x + w; ++cx) {
            if (is_in_bounds(cx, cy)) {
                buffer_[static_cast<size_t>(cy) * static_cast<size_t>(width_) + static_cast<size_t>(cx)] = cell;
            }
        }
    }
}

void Canvas::blit(const Canvas& source, int dest_x, int dest_y) {
    blit(source, dest_x, dest_y, 0, 0, source.width(), source.height());
}

void Canvas::blit(const Canvas& source, int dest_x, int dest_y, int src_x, int src_y, int w, int h) {
    for (int dy = 0; dy < h; ++dy) {
        for (int dx = 0; dx < w; ++dx) {
            int sx = src_x + dx;
            int sy = src_y + dy;
            int tx = dest_x + dx;
            int ty = dest_y + dy;

            if (is_in_bounds(tx, ty)) {
                if (sx >= 0 && sx < source.width() && sy >= 0 && sy < source.height()) {
                    buffer_[static_cast<size_t>(ty) * static_cast<size_t>(width_) + static_cast<size_t>(tx)] = source.at(sx, sy);
                }
            }
        }
    }
}

Style parse_sgr_style(std::string_view sgr) {
    Style s{};
    if (sgr.size() < 3 || sgr[0] != '\033' || sgr[1] != '[') return s;
    const char* p = sgr.data() + 2;
    const char* end = sgr.data() + sgr.size();
    while (p < end && *p != 'm') {
        int code = parse_int(p);
        switch (code) {
            case 0: s = Style{}; break;
            case 1: s.attr = s.attr | Attribute::Bold; break;
            case 2: s.attr = s.attr | Attribute::Dim; break;
            case 4: s.attr = s.attr | Attribute::Underline; break;
            case 30: s.fg = Color::Black; break;
            case 31: s.fg = Color::Red; break;
            case 32: s.fg = Color::Green; break;
            case 33: s.fg = Color::Yellow; break;
            case 34: s.fg = Color::Blue; break;
            case 35: s.fg = Color::Magenta; break;
            case 36: s.fg = Color::Cyan; break;
            case 37: s.fg = Color::White; break;
            case 39: s.fg = Color::Default; break;
            case 90: s.fg = Color::BrightBlack; break;
            case 91: s.fg = Color::BrightRed; break;
            case 92: s.fg = Color::BrightGreen; break;
            case 93: s.fg = Color::BrightYellow; break;
            case 94: s.fg = Color::BrightBlue; break;
            case 95: s.fg = Color::BrightMagenta; break;
            case 96: s.fg = Color::BrightCyan; break;
            case 97: s.fg = Color::BrightWhite; break;
            case 38:
                if (p < end && *p == ';') {
                    p++;
                    int mode = parse_int(p);
                    if (mode == 2 && p < end && *p == ';') {
                        p++; int r = parse_int(p);
                        if (p < end && *p == ';') { p++; int g = parse_int(p);
                            if (p < end && *p == ';') { p++; int b = parse_int(p);
                                s.fg = rgb_color(
                                    static_cast<uint8_t>(r),
                                    static_cast<uint8_t>(g),
                                    static_cast<uint8_t>(b));
                            }
                        }
                    }
                }
                break;
            case 48:
                if (p < end && *p == ';') {
                    p++;
                    int mode = parse_int(p);
                    if (mode == 2 && p < end && *p == ';') {
                        p++; int r = parse_int(p);
                        if (p < end && *p == ';') { p++; int g = parse_int(p);
                            if (p < end && *p == ';') { p++; int b = parse_int(p);
                                s.bg = rgb_color(
                                    static_cast<uint8_t>(r),
                                    static_cast<uint8_t>(g),
                                    static_cast<uint8_t>(b));
                            }
                        }
                    }
                }
                break;
            default: break;
        }
        if (p < end && *p == ';') p++;
        else break;
    }
    return s;
}

} // namespace montauk::ui::widget
