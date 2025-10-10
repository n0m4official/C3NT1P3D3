#include <iostream>
#include <cassert>
#include <vector>
#include <string>
#include "IPRangeValidator.h"

using namespace C3NT1P3D3;

void testPrivateNetworkDetection() {
    auto& validator = IPRangeValidator::getInstance();
    
    std::cout << "Testing private network detection...\n";
    
    // Test private networks
    assert(validator.isPrivateNetwork("192.168.1.1") == true);
    assert(validator.isPrivateNetwork("10.0.0.1") == true);
    assert(validator.isPrivateNetwork("172.16.0.1") == true);
    assert(validator.isPrivateNetwork("172.31.255.255") == true);
    
    // Test public networks
    assert(validator.isPrivateNetwork("8.8.8.8") == false);
    assert(validator.isPrivateNetwork("1.1.1.1") == false);
    
    std::cout << "✅ Private network detection tests passed\n";
}

void testIPValidation() {
    auto& validator = IPRangeValidator::getInstance();
    
    std::cout << "Testing IP validation...\n";
    
    // Valid IPs
    assert(validator.validateIP("192.168.1.1") == true);
    assert(validator.validateIP("10.0.0.1") == true);
    assert(validator.validateIP("255.255.255.255") == true);
    
    // Invalid IPs
    assert(validator.validateIP("256.1.1.1") == false);
    assert(validator.validateIP("192.168.1") == false);
    assert(validator.validateIP("192.168.1.1.1") == false);
    assert(validator.validateIP("abc.def.ghi.jkl") == false);
    
    std::cout << "✅ IP validation tests passed\n";
}

void testCIDRValidation() {
    auto& validator = IPRangeValidator::getInstance();
    
    std::cout << "Testing CIDR validation...\n";
    
    // Valid CIDR
    assert(validator.validateCIDR("192.168.1.0/24") == true);
    assert(validator.validateCIDR("10.0.0.0/8") == true);
    assert(validator.validateCIDR("172.16.0.0/12") == true);
    
    // Invalid CIDR
    assert(validator.validateCIDR("192.168.1.0/33") == false);
    assert(validator.validateCIDR("192.168.1.0/-1") == false);
    assert(validator.validateCIDR("256.1.1.0/24") == false);
    
    std::cout << "✅ CIDR validation tests passed\n";
}

void testRangeSafety() {
    auto& validator = IPRangeValidator::getInstance();
    
    std::cout << "Testing range safety...\n";
    
    // Safe ranges
    assert(validator.isRangeSafe("192.168.1.0/24") == true);
    assert(validator.isRangeSafe("10.0.0.0/8") == true);
    assert(validator.isRangeSafe("172.16.0.0/12") == true);
    
    // Unsafe ranges
    assert(validator.isRangeSafe("8.8.8.0/24") == false);
    assert(validator.isRangeSafe("1.1.1.0/24") == false);
    
    std::cout << "✅ Range safety tests passed\n";
}

void testApprovalRequirements() {
    auto& validator = IPRangeValidator::getInstance();
    
    std::cout << "Testing approval requirements...\n";
    
    // Private ranges should not require approval
    assert(validator.requiresExplicitApproval("192.168.1.0/24") == false);
    assert(validator.requiresExplicitApproval("10.0.0.0/8") == false);
    
    // Public ranges should require approval
    assert(validator.requiresExplicitApproval("8.8.8.0/24") == true);
    assert(validator.requiresExplicitApproval("1.1.1.0/24") == true);
    
    std::cout << "✅ Approval requirements tests passed\n";
}

void testScanPermissions() {
    auto& validator = IPRangeValidator::getInstance();
    
    std::cout << "Testing scan permissions...\n";
    
    // Should allow private networks
    assert(validator.hasScanPermission("192.168.1.0/24") == true);
    assert(validator.hasScanPermission("10.0.0.0/8") == true);
    
    // Should block public networks in strict mode
    validator.setStrictMode(true);
    assert(validator.hasScanPermission("8.8.8.0/24") == false);
    
    std::cout << "✅ Scan permissions tests passed\n";
}

void testLoopbackDetection() {
    auto& validator = IPRangeValidator::getInstance();
    
    std::cout << "Testing loopback detection...\n";
    
    assert(validator.isLoopback("127.0.0.1") == true);
    assert(validator.isLoopback("127.0.0.255") == true);
    assert(validator.isLoopback("192.168.1.1") == false);
    
    std::cout << "✅ Loopback detection tests passed\n";
}

void testMulticastDetection() {
    auto& validator = IPRangeValidator::getInstance();
    
    std::cout << "Testing multicast detection...\n";
    
    assert(validator.isMulticast("224.0.0.1") == true);
    assert(validator.isMulticast("239.255.255.255") == true);
    assert(validator.isMulticast("192.168.1.1") == false);
    
    std::cout << "✅ Multicast detection tests passed\n";
}

void testReservedDetection() {
    auto& validator = IPRangeValidator::getInstance();
    
    std::cout << "Testing reserved IP detection...\n";
    
    assert(validator.isReserved("0.0.0.0") == true);
    assert(validator.isReserved("192.0.2.1") == true);
    assert(validator.isReserved("198.51.100.1") == true);
    assert(validator.isReserved("203.0.113.1") == true);
    assert(validator.isReserved("192.168.1.1") == false);
    
    std::cout << "✅ Reserved IP detection tests passed\n";
}

void testPublicInternetDetection() {
    auto& validator = IPRangeValidator::getInstance();
    
    std::cout << "Testing public internet detection...\n";
    
    assert(validator.isPublicInternet("8.8.8.8") == true);
    assert(validator.isPublicInternet("1.1.1.1") == true);
    assert(validator.isPublicInternet("192.168.1.1") == false);
    assert(validator.isPublicInternet("127.0.0.1") == false);
    assert(validator.isPublicInternet("224.0.0.1") == false);
    
    std::cout << "✅ Public internet detection tests passed\n";
}

int main() {
    std::cout << "🧪 Running IP Range Validator Tests...\n";
    std::cout << "========================================\n\n";
    
    try {
        testPrivateNetworkDetection();
        testIPValidation();
        testCIDRValidation();
        testRangeSafety();
        testApprovalRequirements();
        testScanPermissions();
        testLoopbackDetection();
        testMulticastDetection();
        testReservedDetection();
        testPublicInternetDetection();
        
        std::cout << "\n🎉 All tests passed successfully!\n";
        std::cout << "The IP Range Validator is working correctly.\n";
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Test failed: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}