# password_filter
Windows password filter dll
use encoding utf-16 le bom for all the files
To build:
1. mc -U password_filter.mc
2. rc password_filter.rc

3. cl /DUNICODE /D_UNICODE /LD /EHsc /std:c++17 /Fe:password_filter.dll password_filter.res main_dll.cpp
4. cl /DUNICODE /D_UNICODE /Fe:TestApp.exe /EHsc main_test.cpp /link password_filter.lib //test app
