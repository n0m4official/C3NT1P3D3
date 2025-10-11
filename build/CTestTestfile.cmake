# CMake generated Testfile for 
# Source directory: C:/Users/ba55d/source/repos/C3NT1P3D3
# Build directory: C:/Users/ba55d/source/repos/C3NT1P3D3/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test([=[IPRangeValidatorTest]=] "C:/Users/ba55d/source/repos/C3NT1P3D3/build/Debug/test_ip_validator.exe")
  set_tests_properties([=[IPRangeValidatorTest]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/ba55d/source/repos/C3NT1P3D3/CMakeLists.txt;103;add_test;C:/Users/ba55d/source/repos/C3NT1P3D3/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test([=[IPRangeValidatorTest]=] "C:/Users/ba55d/source/repos/C3NT1P3D3/build/Release/test_ip_validator.exe")
  set_tests_properties([=[IPRangeValidatorTest]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/ba55d/source/repos/C3NT1P3D3/CMakeLists.txt;103;add_test;C:/Users/ba55d/source/repos/C3NT1P3D3/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test([=[IPRangeValidatorTest]=] "C:/Users/ba55d/source/repos/C3NT1P3D3/build/MinSizeRel/test_ip_validator.exe")
  set_tests_properties([=[IPRangeValidatorTest]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/ba55d/source/repos/C3NT1P3D3/CMakeLists.txt;103;add_test;C:/Users/ba55d/source/repos/C3NT1P3D3/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test([=[IPRangeValidatorTest]=] "C:/Users/ba55d/source/repos/C3NT1P3D3/build/RelWithDebInfo/test_ip_validator.exe")
  set_tests_properties([=[IPRangeValidatorTest]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/ba55d/source/repos/C3NT1P3D3/CMakeLists.txt;103;add_test;C:/Users/ba55d/source/repos/C3NT1P3D3/CMakeLists.txt;0;")
else()
  add_test([=[IPRangeValidatorTest]=] NOT_AVAILABLE)
endif()
