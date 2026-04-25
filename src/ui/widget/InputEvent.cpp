#include "ui/widget/InputEvent.hpp"

namespace montauk::ui::widget {

std::vector<InputEvent> parse_input_bytes(const unsigned char* buf, std::size_t n) {
    std::vector<InputEvent> out;
    out.reserve(n);

    for (std::size_t i = 0; i < n;) {
        unsigned char c = buf[i];

        if (c == 0x1B) {
            // Possible CSI sequence: ESC [ ...
            if (i + 1 < n && buf[i + 1] == '[') {
                if (i + 2 < n) {
                    unsigned char a = buf[i + 2];
                    switch (a) {
                        case 'A': out.push_back({Key::ArrowUp,    0}); i += 3; continue;
                        case 'B': out.push_back({Key::ArrowDown,  0}); i += 3; continue;
                        case 'C': out.push_back({Key::ArrowRight, 0}); i += 3; continue;
                        case 'D': out.push_back({Key::ArrowLeft,  0}); i += 3; continue;
                        case 'H': out.push_back({Key::Home,       0}); i += 3; continue;
                        case 'F': out.push_back({Key::End,        0}); i += 3; continue;
                        case '5':
                        case '6': {
                            // CSI 5~ / 6~ → PageUp / PageDown
                            if (i + 3 < n && buf[i + 3] == '~') {
                                out.push_back({a == '5' ? Key::PageUp : Key::PageDown, 0});
                                i += 4;
                                continue;
                            }
                            break;
                        }
                        default: break;
                    }
                }
                // Unrecognized CSI — skip the ESC[ and any digits/intermediate
                // bytes up through a final terminator (0x40-0x7E).
                std::size_t j = i + 2;
                while (j < n) {
                    unsigned char x = buf[j++];
                    if (x >= 0x40 && x <= 0x7E) break;
                }
                i = j;
                continue;
            }
            // Bare Escape.
            out.push_back({Key::Escape, 0});
            ++i;
            continue;
        }

        if (c == '\r' || c == '\n') { out.push_back({Key::Enter, 0});     ++i; continue; }
        if (c == 0x7F || c == 0x08) { out.push_back({Key::Backspace, 0}); ++i; continue; }
        if (c == 0x09)              { out.push_back({Key::Tab, 0});       ++i; continue; }

        // Plain byte — treat as Char (covers printable ASCII + ctrl chars).
        // Widgets can filter via is_printable_char() if they only want printable.
        out.push_back({Key::Char, static_cast<char>(c)});
        ++i;
    }

    return out;
}

} // namespace montauk::ui::widget
