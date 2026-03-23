#include "app/MetricsServer.hpp"

namespace montauk::app {

MetricsServer::MetricsServer(const SnapshotBuffers& buffers, uint16_t port,
                             const TraceBuffers* trace)
    : buffers_(buffers), trace_(trace), port_(port) {}

MetricsServer::~MetricsServer() = default;

void MetricsServer::start() {}
void MetricsServer::stop() {}

} // namespace montauk::app
