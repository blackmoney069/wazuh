#ifndef _BASE_ERROR_HPP
#define _BASE_ERROR_HPP

#include <optional>
#include <string>
#include <variant>

namespace base
{
/**
 * @brief The Error struct
 *
 * The Error struct is used to represent an error string in the Engine.
 * !note This struct is needed to desambiguate between a content string and an Error
 * string on variants.
 *
 */
struct Error
{
    std::string message; ///< Error message
};

using OptError = std::optional<Error>;      ///< Optional Error
template<typename T>
using RespOrError = std::variant<T, Error>; ///< T or Error

/**
 * @brief Return no error
 *
 * @return OptError
 */
inline OptError noError()
{
    return std::nullopt;
}

/**
 * @brief Check if an error is present
 *
 * @param error
 * @return true if error is present
 * @return false otherwise
 */
inline bool isError(const OptError& error)
{
    return error.has_value();
}

/**
 * @brief Check if a response is an error
 *
 * @tparam T Type of the response
 * @param respOrError
 * @return true if response is an error
 * @return false otherwise
 */
template<typename T>
inline bool isError(const RespOrError<T>& respOrError)
{
    return std::holds_alternative<Error>(respOrError);
}

/**
 * @brief Get the Response object
 *
 * @note This function should be used only if isError(respOrError) returns false
 *
 * @tparam T Type of the response
 * @param response
 * @return T
 *
 * @throws std::bad_variant_access if response is an error
 */
template<typename T>
inline T getResponse(RespOrError<T>&& response)
{
    return std::get<T>(std::move(response));
}

} // namespace base

#endif // _BASE_ERROR_HPP
