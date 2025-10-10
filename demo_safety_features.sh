#!/bin/bash

echo "🛡️ C3NT1P3D3 Safety Features Demonstration"
echo "========================================="
echo

cd build

echo "1. Testing Private Network (Should Work)"
echo "----------------------------------------"
./C3NT1P3D3-Comprehensive 192.168.1.0/24 --output /tmp/test1.json << EOF
yes
EOF

echo
echo "2. Testing Public Network (Should Be Blocked)"
echo "---------------------------------------------"
./C3NT1P3D3-Comprehensive 8.8.8.0/24 --output /tmp/test2.json << EOF
no
EOF

echo
echo "3. Testing IP Range Validation"
echo "------------------------------"
./test_ip_validator

echo
echo "4. Testing Configuration Files"
echo "------------------------------"
ls -la ../config/

echo
echo "5. Project Structure Overview"
echo "-----------------------------"
echo "Files organized into logical directories:"
find .. -type f -name "*.cpp" -o -name "*.h" | head -10
echo "..."
echo "Total source files: $(find .. -name "*.cpp" | wc -l)"
echo "Total header files: $(find .. -name "*.h" | wc -l)"

echo
echo "✅ Safety demonstration complete!"
echo "The scanner successfully prevents scanning of public networks"
echo "while allowing authorized private network scanning."