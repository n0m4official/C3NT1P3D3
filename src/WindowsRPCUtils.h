#pragma once
#include <windows.h>
#include <rpcdce.h>
#include <lm.h>
#include <string>

typedef unsigned long NET_API_STATUS;

struct NETLOGON_CREDENTIAL {
    char data[8];
};

extern "C" {
NET_API_STATUS __stdcall NetrServerReqChallenge(
    handle_t h,
    wchar_t* server_name,
    wchar_t* computer_name,
    NETLOGON_CREDENTIAL* client_challenge,
    NETLOGON_CREDENTIAL* server_challenge
);
}

class RPCBinding {
public:
    RPCBinding(const std::wstring& target);
    ~RPCBinding();
    operator handle_t() const { return binding_; }
    
private:
    handle_t binding_ = nullptr;
};
