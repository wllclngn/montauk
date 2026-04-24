#include "ui/widget/Component.hpp"
#include <sstream>
#include <iomanip>

namespace montauk::ui::widget {

LayoutRect Component::draw_box_border(
    Canvas& canvas,
    const LayoutRect& rect,
    const std::string& title,
    Style border_style,
    Style title_style
) const {
    canvas.draw_rect(rect.x, rect.y, rect.width, rect.height, border_style);

    if (!title.empty() && rect.width > 4) {
        // Center the title along the top border, matching the pre-refactor
        // make_box layout: [TL][─×left][ title ][─×right][TR].
        const std::string t = " " + title + " ";
        const int span = rect.width - 2;  // usable cells between corners
        const int tlen = static_cast<int>(t.size());
        const int pad_left = std::max(0, (span - tlen) / 2);
        canvas.draw_text(rect.x + 1 + pad_left, rect.y, t, title_style);
    }

    return LayoutRect{
        rect.x + 1,
        rect.y + 1,
        rect.width - 2,
        rect.height - 2
    };
}

std::string Component::format_duration(int total_seconds) const {
    int hours = total_seconds / 3600;
    int minutes = (total_seconds % 3600) / 60;
    int seconds = total_seconds % 60;

    std::ostringstream oss;
    if (hours > 0) {
        oss << hours << ":"
            << std::setw(2) << std::setfill('0') << minutes << ":"
            << std::setw(2) << std::setfill('0') << seconds;
    } else {
        oss << minutes << ":"
            << std::setw(2) << std::setfill('0') << seconds;
    }
    return oss.str();
}

std::string Component::center_text(const std::string& text, int width) const {
    if (static_cast<int>(text.length()) >= width) {
        return text.substr(0, static_cast<size_t>(width));
    }

    int padding = (width - static_cast<int>(text.length())) / 2;
    return std::string(static_cast<size_t>(padding), ' ') + text;
}

std::string Component::pad_right(const std::string& text, int width) const {
    if (static_cast<int>(text.length()) >= width) {
        return text.substr(0, static_cast<size_t>(width));
    }
    return text + std::string(static_cast<size_t>(width) - text.length(), ' ');
}

std::string Component::format_filesize(size_t bytes) const {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int unit_index = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unit_index < 3) {
        size /= 1024.0;
        unit_index++;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size << " " << units[unit_index];
    return oss.str();
}

} // namespace montauk::ui::widget
