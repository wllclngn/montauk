// vector -- agent-facing MCP tool surface over montauk/sublimation.
// Read-only / observational only: no killing processes, no scheduler-policy
// changes, nothing mutating, in any of the four tools (see tools.rs).
//
// Thin wrapper: the dispatch logic lives in the library (tools.rs) so
// tests/test_mcp_tools.rs can exercise it directly, the same way
// tests/test_mcp_json.rs and tests/test_mcp_rpc.rs already exercise
// json.rs and rpc.rs.

use vector::{ffi, rpc, tools::ToolServer};

fn main() {
    if std::env::args().any(|a| a == "--version") {
        println!("vector {} (sublimation api v{}, {})",
                  env!("CARGO_PKG_VERSION"), ffi::api_version(), ffi::version());
        return;
    }
    let mut server = ToolServer;
    rpc::run(&mut server);
}
