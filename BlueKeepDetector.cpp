#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <stdexcept>
#include <system_error>
#include <chrono>
#include <thread>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

enum class ExploitSeverity {
    Critical,
    // other severities if needed
};

struct ExploitResult {
    bool success;
    std::string message;
    std::string TargetHost;

    ExploitResult(bool s, std::string m, std::string host)
        : success(s), message(std::move(m)), TargetHost(std::move(host)) {
    }
};

class BlueKeepDetector {
public:
    std::string Name() const {
        return "BlueKeep Vulnerability Detector";
    }

    std::string Description() const {
        return "Safely checks if RDP is accessible and shows signs that might relate to CVE-2019-0708 (BlueKeep).";
    }

    ExploitSeverity Severity() const {
        return ExploitSeverity::Critical;
    }

    ExploitResult Run(const std::string& targetHost) {
        WSADATA wsaData;
        SOCKET ConnectSocket = INVALID_SOCKET;
        struct addrinfo* result = nullptr,
            * ptr = nullptr,
            hints;

        int iResult;

        iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            return ExploitResult(false, "WSAStartup failed with error: " + std::to_string(iResult), targetHost);
        }

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        iResult = getaddrinfo(targetHost.c_str(), "3389", &hints, &result);
        if (iResult != 0) {
            WSACleanup();
            return ExploitResult(false, "getaddrinfo failed with error: " + std::to_string(iResult), targetHost);
        }

        bool connected = false;
        for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
            ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (ConnectSocket == INVALID_SOCKET) {
                WSACleanup();
                return ExploitResult(false, "Error at socket(): " + std::to_string(WSAGetLastError()), targetHost);
            }

            // Set socket to non-blocking for timeout
            u_long mode = 1;
            ioctlsocket(ConnectSocket, FIONBIO, &mode);

            iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
            if (iResult == SOCKET_ERROR) {
                if (WSAGetLastError() != WSAEWOULDBLOCK) {
                    closesocket(ConnectSocket);
                    ConnectSocket = INVALID_SOCKET;
                    continue;
                }
            }

            // Wait for connection with timeout 3000ms
            fd_set writeSet;
            FD_ZERO(&writeSet);
            FD_SET(ConnectSocket, &writeSet);
            timeval tv;
            tv.tv_sec = 3;
            tv.tv_usec = 0;

            iResult = select(0, nullptr, &writeSet, nullptr, &tv);
            if (iResult > 0 && FD_ISSET(ConnectSocket, &writeSet)) {
                // Check for socket error
                int so_error = 0;
                int len = sizeof(so_error);
                getsockopt(ConnectSocket, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
                if (so_error == 0) {
                    connected = true;
                    break;
                }
            }

            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
        }

        freeaddrinfo(result);

        if (!connected || ConnectSocket == INVALID_SOCKET) {
            WSACleanup();
            return ExploitResult(false, "RDP port is closed or unreachable.", targetHost);
        }

        // Set socket back to blocking mode
        u_long mode = 0;
        ioctlsocket(ConnectSocket, FIONBIO, &mode);

        // Prepare connection request bytes
        std::array<unsigned char, 16> connectionRequest = {
            0x03, 0x00, 0x00, 0x13,
            0x0E, 0xE0, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x08, 0x03, 0x00
        };

        // Send connection request
        int sendResult = send(ConnectSocket, reinterpret_cast<const char*>(connectionRequest.data()), (int)connectionRequest.size(), 0);
        if (sendResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            WSACleanup();
            return ExploitResult(false, "Socket error while attempting connection to RDP.", targetHost);
        }

        // Receive response (11 bytes)
        std::vector<unsigned char> response(11);
        int totalReceived = 0;
        while (totalReceived < 11) {
            int bytesReceived = recv(ConnectSocket, reinterpret_cast<char*>(response.data() + totalReceived), 11 - totalReceived, 0);
            if (bytesReceived == 0) {
                // Connection closed
                closesocket(ConnectSocket);
                WSACleanup();
                return ExploitResult(false, "Connection closed by server before negotiation completed.", targetHost);
            }
            if (bytesReceived == SOCKET_ERROR) {
                closesocket(ConnectSocket);
                WSACleanup();
                return ExploitResult(false, "Socket error while attempting connection to RDP.", targetHost);
            }
            totalReceived += bytesReceived;
        }

        closesocket(ConnectSocket);
        WSACleanup();

        if (totalReceived < 11) {
            return ExploitResult(false, "Unexpected response from RDP server.", targetHost);
        }

        switch (response[5]) {
        case 0xD0:
            return ExploitResult(true, "RDP is accessible. Target might be vulnerable to BlueKeep if unpatched.", targetHost);
        case 0xF0:
            return ExploitResult(false, "RDP refused the connection — likely patched or restricted.", targetHost);
        default:
            return ExploitResult(false, "RDP responded, but the format was unrecognized.", targetHost);
        }
    }
};