#include "CoreEngine.h"
#include <chrono>
#include <ctime>
#include <sstream>

struct CoreEngine::Impl
{
	bool simulation = true;
	std::string runId;
};

CoreEngine::CoreEngine(bool simulationOnly) : pImpl(new Impl())
{
	pImpl->simulation = simulationOnly;
	// Generate a simple run ID based on timestamp
	auto now = std::chrono::system_clock::now();
	std::time_t t = std::chrono::system_clock::to_time_t(now);

	char buffer[26]; // ctime_s needs at least 26 chars
#ifdef _WIN32
	if (ctime_s(buffer, sizeof(buffer), &t) == 0) {
#else
	if (ctime_r(&t, buffer) != nullptr) {
#endif
		pImpl->runId = std::string(buffer);
		// remove trailing newline
		if (!pImpl->runId.empty() && pImpl->runId.back() == '\n') {
			pImpl->runId.pop_back();
		}
	}
	else {
		pImpl->runId = "unknown-time";
	}

}

CoreEngine::~CoreEngine()
{
	delete pImpl;
}

bool CoreEngine::simulationMode() const
{
	return pImpl->simulation;
}

std::string CoreEngine::runId() const
{
	return pImpl->runId;
}