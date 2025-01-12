#include <windows.h>
#include <unordered_map>
#include <iostream>
#include <string>
#include <ntsecapi.h>
#include <memory>
#include <locale>    // For handling locales
#include <codecvt>   // For conversion between character types

// Forward declaration of functions in your DLL
extern "C" {
    __declspec(dllimport) BOOLEAN PasswordFilter(
        PUNICODE_STRING AccountName,
        PUNICODE_STRING FullName,
        PUNICODE_STRING Password,
        BOOLEAN SetOperation);
}

void setupConsole() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8); 
    std::locale::global(std::locale(""));
}

PUNICODE_STRING CreateUnicodeString(const std::wstring& str) {
    auto unicodeString = new UNICODE_STRING;
    unicodeString->Length = static_cast<USHORT>(str.length() * sizeof(wchar_t));
    unicodeString->MaximumLength = unicodeString->Length + sizeof(wchar_t); // Include space for null terminator
    unicodeString->Buffer = new wchar_t[unicodeString->MaximumLength / sizeof(wchar_t)];
    
    // Copy string into buffer
    wcsncpy_s(unicodeString->Buffer, unicodeString->MaximumLength / sizeof(wchar_t), str.c_str(), str.length());
    unicodeString->Buffer[str.length()] = L'\0'; // Null-terminate

    return unicodeString; // Return the created UNICODE_STRING
}

// Cleanup function for PUNICODE_STRING
void DeleteUnicodeString(PUNICODE_STRING unicodeString) {
    if (unicodeString) {
        delete[] unicodeString->Buffer; // Free the allocated buffer
        delete unicodeString; // Delete the structure itself
    }
}

int main() {
    setupConsole();
    
    auto accountName = CreateUnicodeString(L"tester");
    auto fullName = CreateUnicodeString(L"Test User"); // Simulate full name
    std::wstring pass = L"ЙйЙй100500";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"Йцукен600600";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"QqQq1234567890";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"Lviv1234567890";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"Qwertyuiop[]789";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"QWErty1234567890";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"Njvfc1234567890";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"\";lkjhgfdsA987";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"!234567Qwertyu";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"Nazar0987654321";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"QQww0987654321";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
        pass = L"Njvfc1234567890";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"SDsd1234567890";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"Namor1234567890";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"Zaqw@1234567890";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"Watch987654321";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"AaAa1234567890";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"Zxcvbnm,./12345";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    pass = L"QAZqaz0987654321";
    if (!PasswordFilter(accountName, fullName, CreateUnicodeString(pass), TRUE)) {
        std::wcout << L"Test ok for pass: " << pass << std::endl;
    } else {
        std::wcout << L"Test failed for pass: " << pass << std::endl;
    }
    while (true) {
        std::wcout << std::endl << L"Enter a password (or 'exit' to quit): ";
        std::wstring passwordInput;
        std::getline(std::wcin, passwordInput);
        auto password = CreateUnicodeString(passwordInput);
        // Log the raw input captured
        std::wcout << L"Raw Password entered: " << passwordInput << std::endl;
        std::wcout << L"Length of Password entered: " << passwordInput.length() << std::endl;
        //std::wcin.ignore(1024, L'\n');
        // Check if the input was empty
        if (passwordInput.empty()) {
            std::wcout << L"Attempted to enter an empty password."; // Log empty case
            continue; // Repeat the loop without processing
        }
        if (passwordInput == L"exit") {
            break; // Exit the loop if the user types "exit"
        }

        

        // Test the entered password
        if (PasswordFilter(accountName, fullName, password, TRUE)) {
            std::wcout << L"Password accepted: " << passwordInput << std::endl;
        } else {
            std::wcerr << L"Password rejected: " << passwordInput << std::endl;
        }

        std::wcout << L"Password checked" << std::endl;
        // Clean up allocated password string
        DeleteUnicodeString(password);
    }
    return 0;
}