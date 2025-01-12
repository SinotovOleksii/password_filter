#include <windows.h>
#include <unordered_map>
#include <iostream>
#include <string>
#include <ntsecapi.h>
#include <memory>
#include <locale>    // For handling locales
#include <codecvt>   // For conversion between character types

std::unordered_map<wchar_t, wchar_t> ruToEnMap = {
        {L'ё', L'`'}, {L'Ё', L'~'},
        {L'й', L'q'}, {L'ц', L'w'}, {L'у', L'e'}, {L'к', L'r'}, {L'е', L't'}, {L'н', L'y'}, {L'г', L'u'}, {L'ш', L'i'}, {L'щ', L'o'}, {L'з', L'p'}, {L'х', L'['}, {L'ъ', L']'}, 
        {L'ф', L'a'}, {L'ы', L's'}, {L'в', L'd'}, {L'а', L'f'}, {L'п', L'g'}, {L'р', L'h'}, {L'о', L'j'}, {L'л', L'k'}, {L'д', L'l'}, {L'ж', L';'}, {L'э', L'\''}, {L'\\', L'\\'},
        {L'я', L'z'}, {L'ч', L'x'}, {L'с', L'c'}, {L'м', L'v'}, {L'и', L'b'}, {L'т', L'n'}, {L'ь', L'm'}, {L'б', L','}, {L'ю', L'.'}, {L'.', L'/'}, 
        {L'!', L'!'}, {L'"', L'@'}, {L'№', L'#'}, {L';', L'$'}, {L'%', L'%'}, {L':', L'^'}, {L'?', L'&'}, {L'*', L'*'}, {L'(', L'('}, {L')', L')'}, {L'_', L'_'}, {L'+', L'+'},
        {L'Й', L'Q'}, {L'Ц', L'W'}, {L'У', L'E'}, {L'К', L'R'}, {L'Е', L'T'}, {L'Н', L'Y'}, {L'Г', L'U'}, {L'Ш', L'I'}, {L'Щ', L'O'}, {L'З', L'P'}, {L'Х', L'{'}, {L'Ъ', L'}'}, 
        {L'Ф', L'A'}, {L'Ы', L'S'}, {L'В', L'D'}, {L'А', L'F'}, {L'П', L'G'}, {L'Р', L'H'}, {L'О', L'J'}, {L'Л', L'K'}, {L'Д', L'L'}, {L'Ж', L':'}, {L'Э', L'\"'}, {L'/', L'|'},
        {L'Я', L'Z'}, {L'Ч', L'X'}, {L'С', L'C'}, {L'М', L'V'}, {L'И', L'B'}, {L'Т', L'N'}, {L'Ь', L'M'}, {L'Б', L'<'}, {L'Ю', L'>'}, {L',', L'?'}, 
    };
std::unordered_map<wchar_t, wchar_t> uaToEnMap = {
        {L'\'', L'`'}, {L'₴', L'~'},
        {L'й', L'q'}, {L'ц', L'w'}, {L'у', L'e'}, {L'к', L'r'}, {L'е', L't'}, {L'н', L'y'}, {L'г', L'u'}, {L'ш', L'i'}, {L'щ', L'o'}, {L'з', L'p'}, {L'х', L'['}, {L'ї', L']'}, 
        {L'ф', L'a'}, {L'і', L's'}, {L'в', L'd'}, {L'а', L'f'}, {L'п', L'g'}, {L'р', L'h'}, {L'о', L'j'}, {L'л', L'k'}, {L'д', L'l'}, {L'ж', L';'}, {L'є', L'\''}, {L'\\', L'\\'},
        {L'я', L'z'}, {L'ч', L'x'}, {L'с', L'c'}, {L'м', L'v'}, {L'и', L'b'}, {L'т', L'n'}, {L'ь', L'm'}, {L'б', L','}, {L'ю', L'.'}, {L'.', L'/'}, 
        {L'!', L'!'}, {L'"', L'@'}, {L'№', L'#'}, {L';', L'$'}, {L'%', L'%'}, {L':', L'^'}, {L'?', L'&'}, {L'*', L'*'}, {L'(', L'('}, {L')', L')'}, {L'_', L'_'}, {L'+', L'+'},
        {L'Й', L'Q'}, {L'Ц', L'W'}, {L'У', L'E'}, {L'К', L'R'}, {L'Е', L'T'}, {L'Н', L'Y'}, {L'Г', L'U'}, {L'Ш', L'I'}, {L'Щ', L'O'}, {L'З', L'P'}, {L'Х', L'{'}, {L'Ї', L'}'}, 
        {L'Ф', L'A'}, {L'І', L'S'}, {L'В', L'D'}, {L'А', L'F'}, {L'П', L'G'}, {L'Р', L'H'}, {L'О', L'J'}, {L'Л', L'K'}, {L'Д', L'L'}, {L'Ж', L':'}, {L'Є', L'\"'}, {L'/', L'|'},
        {L'Я', L'Z'}, {L'Ч', L'X'}, {L'С', L'C'}, {L'М', L'V'}, {L'И', L'B'}, {L'Т', L'N'}, {L'Ь', L'M'}, {L'Б', L'<'}, {L'Ю', L'>'}, {L',', L'?'}, 
    };

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
    // std::string password1 = "QqQq100500";
    // std::string password3 = "ЙйЙй100500";
    // std::wstring widePass = StringToWString(password3);
    // std::cout << "std:string " << password3 << std::endl;
    // //std::wcout << L"std::wstr " << widePass << std::endl;
    // //std::cout << std::endl << "end with " << widePass.length() << std::endl;
    // std::wcout << L"Hexadecimal representation of the wide string:" << std::endl;
    // for (const auto& ch : widePass) {
    //     // Print each character's hex value
    //     std::wcout << std::hex << L"0x" << (int)ch << L" "; // cast to int for proper output
    // }
    // std::wcout << std::endl; // New line after hex output

    // auto password = CreateUnicodeString(password1);
    // if (PasswordFilter(accountName, fullName, password, TRUE)) {
    //          std::wcout << L"Password accepted: " << StringToWString(password1) << std::endl;
    //      } else {
    //          std::wcerr << L"Password rejected: " << StringToWString(password1) << std::endl;
    // }
    // std::wcout << L"Second pass test: "  << std::endl;
    // password = CreateUnicodeString(password3);
    // if (PasswordFilter(accountName, fullName, password, TRUE)) {
    //          std::wcout << L"Password accepted: " << StringToWString(password3) << std::endl;
    //      } else {
    //          std::wcerr << L"Password rejected: " << StringToWString(password3) << std::endl;
    // }
    // Clean up allocated strings
    // DeleteUnicodeString(accountName);
    // DeleteUnicodeString(fullName);

    // std::wcout << L"Program exited." << std::endl;
    // return 0;

    //std::string passwordStr = "ЙйЙй100500"; // Hardcoded password with Cyrillic input

    // Clean up


    return 0;
}