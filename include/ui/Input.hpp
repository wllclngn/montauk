#pragma once

namespace montauk::ui {

// Process keyboard input and update UI state
// Returns true if should quit
bool handle_keyboard_input(int sleep_ms_ref, bool& show_help);

// Helper to check for available input
bool has_input_available(int timeout_ms);

} // namespace montauk::ui
