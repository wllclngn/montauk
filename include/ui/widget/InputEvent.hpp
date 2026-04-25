#pragma once

#include <cstddef>
#include <vector>

namespace montauk::ui::widget {

// Logical key types. Char carries an ASCII byte in `character`; everything
// else is a named key. The parser maps escape sequences to these enum
// values so widgets can match by name without re-decoding.
enum class Key {
    None,
    Char,
    Enter,
    Backspace,
    Escape,
    Tab,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    PageUp,
    PageDown,
    Home,
    End,
};

struct InputEvent {
    Key  key       = Key::None;
    char character = 0;          // valid when key == Key::Char

    [[nodiscard]] bool is(Key k)              const { return key == k; }
    [[nodiscard]] bool is_char(char c)        const { return key == Key::Char && character == c; }
    [[nodiscard]] bool is_printable_char()    const {
        return key == Key::Char && static_cast<unsigned char>(character) >= 0x20
                                && static_cast<unsigned char>(character) < 0x7F;
    }
};

// Parse a buffer of raw stdin bytes (read in non-blocking mode) into a
// sequence of InputEvents. Recognizes:
//   - Printable ASCII → Key::Char
//   - Enter (\r or \n), Backspace (0x7F or 0x08), Tab (0x09)
//   - Bare Escape (0x1B with no follow-up), or:
//   - CSI sequences for arrows (ESC [ A/B/C/D), Home/End (H/F),
//     PageUp/PageDown (5~ / 6~).
// Anything unrecognized is skipped silently — terminal junk shouldn't
// produce phantom keystrokes.
[[nodiscard]] std::vector<InputEvent> parse_input_bytes(const unsigned char* buf, std::size_t n);

} // namespace montauk::ui::widget
