#include "app/MetricsServer.hpp"

namespace montauk::app {

MetricsServer::MetricsServer(const SnapshotBuffers& buffers, uint16_t port)
    : buffers_(buffers), port_(port) {}

MetricsServer::~MetricsServer() = default;

void MetricsServer::start() {}
void MetricsServer::stop() {}

} // namespace montauk::app
