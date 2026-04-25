#include "ui/widget/FlexLayout.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace montauk::ui::widget {

void FlexLayout::add_item(const LayoutConstraints& constraints) {
    items_.push_back(FlexItem{constraints});
}

std::vector<LayoutRect> FlexLayout::compute_layout(int available_width, int available_height) {
    if (items_.empty()) return {};

    std::vector<int> main_sizes = compute_main_axis_sizes(
        direction_ == FlexDirection::Row ? available_width : available_height);
    std::vector<int> cross_sizes = compute_cross_axis_sizes(
        direction_ == FlexDirection::Row ? available_height : available_width);

    std::vector<LayoutRect> result;
    result.reserve(items_.size());

    int main_pos = 0;
    for (size_t i = 0; i < items_.size(); ++i) {
        LayoutRect rect;
        if (direction_ == FlexDirection::Row) {
            rect.x = main_pos;
            rect.y = 0;
            rect.width = main_sizes[i];
            rect.height = cross_sizes[i];
        } else {
            rect.x = 0;
            rect.y = main_pos;
            rect.width = cross_sizes[i];
            rect.height = main_sizes[i];
        }
        main_pos += main_sizes[i] + spacing_;
        result.push_back(rect);
    }

    return result;
}

std::vector<int> FlexLayout::compute_main_axis_sizes(int available_space) {
    const size_t n = items_.size();
    std::vector<int> sizes(n, 0);
    std::vector<bool> frozen(n, false);
    const bool is_width = (direction_ == FlexDirection::Row);

    // 1. Initialize at the basis (preferred-or-min).
    int used_space = 0;
    for (size_t i = 0; i < n; ++i) {
        int basis = 0;
        if (is_width) {
            basis = items_[i].constraints.size.preferred_width.value_or(
                items_[i].constraints.size.min_width.value_or(0));
        } else {
            basis = items_[i].constraints.size.preferred_height.value_or(
                items_[i].constraints.size.min_height.value_or(0));
        }
        sizes[i] = basis;
        used_space += basis;
    }
    if (n > 1) used_space += spacing_ * static_cast<int>(n - 1);

    // 2. Iterate, freezing items that hit min/max so the next pass
    //    redistributes among the still-flexible ones. Standard flexbox.
    while (true) {
        const int free_space = available_space - used_space;
        if (free_space == 0) break;

        float total_flex = 0.0f;
        for (size_t i = 0; i < n; ++i) {
            if (frozen[i]) continue;
            total_flex += (free_space > 0)
                              ? items_[i].constraints.flex.flex_grow
                              : items_[i].constraints.flex.flex_shrink;
        }
        if (total_flex <= 0.0f) break;

        bool violation = false;
        std::vector<int> proposed = sizes;
        const double dist = static_cast<double>(free_space);

        for (size_t i = 0; i < n; ++i) {
            if (frozen[i]) continue;
            const float flex = (free_space > 0)
                                   ? items_[i].constraints.flex.flex_grow
                                   : items_[i].constraints.flex.flex_shrink;
            if (flex <= 0.0f) continue;

            const double share = dist * (static_cast<double>(flex) / total_flex);
            const int delta = static_cast<int>(std::round(share));
            const int tentative = sizes[i] + delta;
            const int min_s = get_min_size(items_[i].constraints.size, is_width);
            const int max_s = get_max_size(items_[i].constraints.size, is_width);

            if (tentative < min_s) {
                sizes[i] = min_s;
                frozen[i] = true;
                violation = true;
                break;
            }
            if (tentative > max_s) {
                sizes[i] = max_s;
                frozen[i] = true;
                violation = true;
                break;
            }
            proposed[i] = tentative;
        }

        if (violation) {
            used_space = 0;
            for (int s : sizes) used_space += s;
            if (n > 1) used_space += spacing_ * static_cast<int>(n - 1);
            continue;
        }

        sizes = proposed;

        // Drop any rounding remainder onto the last unfrozen flex item
        // so the column fills exactly.
        int final_used = 0;
        for (int s : sizes) final_used += s;
        if (n > 1) final_used += spacing_ * static_cast<int>(n - 1);
        const int remainder = available_space - final_used;
        if (remainder != 0) {
            for (int i = static_cast<int>(n) - 1; i >= 0; --i) {
                if (frozen[i]) continue;
                const float flex = (free_space > 0)
                                       ? items_[i].constraints.flex.flex_grow
                                       : items_[i].constraints.flex.flex_shrink;
                if (flex > 0.0f) {
                    sizes[i] += remainder;
                    const int min_s = get_min_size(items_[i].constraints.size, is_width);
                    const int max_s = get_max_size(items_[i].constraints.size, is_width);
                    sizes[i] = std::clamp(sizes[i], min_s, max_s);
                    break;
                }
            }
        }
        break;
    }

    return sizes;
}

std::vector<int> FlexLayout::compute_cross_axis_sizes(int available_space) {
    std::vector<int> sizes(items_.size(), 0);
    const bool is_width = (direction_ == FlexDirection::Column);

    for (size_t i = 0; i < items_.size(); ++i) {
        const auto& c = items_[i].constraints.size;
        int size = available_space;  // default: stretch
        if (is_width && c.preferred_width)        size = *c.preferred_width;
        else if (!is_width && c.preferred_height) size = *c.preferred_height;
        size = clamp_to_constraints(size, c, is_width);
        sizes[i] = size;
    }
    return sizes;
}

int FlexLayout::clamp_to_constraints(int size, const SizeConstraints& c, bool is_width) const {
    return std::clamp(size, get_min_size(c, is_width), get_max_size(c, is_width));
}

int FlexLayout::get_min_size(const SizeConstraints& c, bool is_width) const {
    if (is_width  && c.min_width)  return *c.min_width;
    if (!is_width && c.min_height) return *c.min_height;
    return 0;
}

int FlexLayout::get_max_size(const SizeConstraints& c, bool is_width) const {
    if (is_width  && c.max_width)  return *c.max_width;
    if (!is_width && c.max_height) return *c.max_height;
    return std::numeric_limits<int>::max();
}

} // namespace montauk::ui::widget
