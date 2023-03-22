#ifndef _I_METRICS_MANAGER_H
#define _I_METRICS_MANAGER_H

#include <string>
#include <unordered_map>
#include <vector>

namespace metrics_manager
{

class IMetricsScope;

class IMetricsManager
{
public:
    /// @brief Configure and Start the Metrics Manager
    virtual void start() = 0;

    /// @brief Returns if the Metrics Manager is running or not.
    /// @return Running status. 
    virtual bool isRunning() = 0;

    /// @brief Gets a Metrics Scope Handler given it's name. 
    /// If it doesn't exists, the Manager creates a new one.
    /// If it does already exists, the Manager returns the Handler.
    /// @param name The name of the Scope.
    /// @return Handler of the Scope.
    virtual std::shared_ptr<IMetricsScope> getMetricsScope(const std::string& name) = 0;

    /// @brief Returns the names of all the scopes in the Metrics Nodule.
    /// @return vector of strings containing the names of the existing scopes.
    virtual std::vector<std::string> getScopeNames() = 0;
};

} // namespace metrics_manager

#endif // _I_METRICS_MANAGER_H