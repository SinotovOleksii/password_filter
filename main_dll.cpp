#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <ntsecapi.h>
#include <fstream>
#include <vector>
#include <string>
#include <wchar.h>
#include <cwctype>
#include <unordered_map>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <mutex>          // Required for std::mutex and std::lock_guard
#include <filesystem>     // Required for std::filesystem
#include <locale>

#include "password_filter.h" //msg resource eventlog
#pragma comment(lib, "advapi32.lib")

const wchar_t* PROVIDER_NAME = L"CustomPasswordFilter";
const int MAX_PATTERN_LENGTH = 10;
const int MIN_PATTERN_LENGTH = 4;
const wchar_t* PATTERN_FILE = L"restricted_patterns.txt";
const wchar_t* LOG_FILE = L"password_filter.log";
const wchar_t* LOG_DATETIME_FORMAT = L"%d.%m.%Y %H:%M:%S";
const size_t MAX_LOG_SIZE = 2 * 1024 * 1024;
const wchar_t* ROTATE_FILENAME_SUFIX = L"%d%m%Y";


std::mutex logMutex; // log file mutex

std::mutex patternMutex; // Mutex for thread safety load restricted patterns

std::vector<std::wstring> restrictedPatterns; //contain patterns loaded by rules

std::filesystem::file_time_type lastWriteTime; //last changed time of PATTERN_FILE file

//map for standardize the password keyboard layout to EN

std::unordered_map<wchar_t, wchar_t> combinedMap = {
    {L'ё', L'`'}, {L'Ё', L'~'},
    {L'й', L'q'}, {L'Ц', L'w'}, {L'у', L'e'}, {L'к', L'r'}, {L'е', L't'}, {L'н', L'y'}, {L'г', L'u'}, {L'ш', L'i'}, {L'щ', L'o'}, {L'з', L'p'}, {L'х', L'['}, {L'ъ', L']'},
    {L'ф', L'a'}, {L'ы', L's'}, {L'в', L'd'}, {L'а', L'f'}, {L'п', L'g'}, {L'р', L'h'}, {L'о', L'j'}, {L'л', L'k'}, {L'д', L'l'}, {L'ж', L';'}, {L'э', L'\''},
    {L'я', L'z'}, {L'ч', L'x'}, {L'с', L'c'}, {L'м', L'v'}, {L'и', L'b'}, {L'т', L'n'}, {L'ь', L'm'}, {L'б', L','}, {L'ю', L'.'},
    {L'!', L'!'}, {L'"', L'@'}, {L'№', L'#'}, {L';', L'$'}, {L'%', L'%'}, {L':', L'^'}, {L'?', L'&'}, {L'*', L'*'}, {L'(', L'('}, {L')', L')'},
    {L'₴', L'~'}, // Ukrainian currency symbol
    {L'і', L's'}, // Note: 'і' 
    {L'ї', L']'}, // Unique to Ukrainian
    {L'є', L'\''}, // Unique to Ukrainian
    {L'.', L'/'},   // Unique to Ukrainian
    {L'Й', L'Q'}, {L'Ц', L'W'}, {L'У', L'E'}, {L'К', L'R'}, {L'Е', L'T'}, {L'Н', L'Y'}, {L'Г', L'U'}, {L'Ш', L'I'}, {L'Щ', L'O'}, {L'З', L'P'}, {L'Х', L'{'}, {L'Ъ', L'}'},
    {L'Ф', L'A'}, {L'Ы', L'S'}, {L'В', L'D'}, {L'А', L'F'}, {L'П', L'G'}, {L'Р', L'H'}, {L'О', L'J'}, {L'Л', L'K'}, {L'Д', L'L'}, {L'Ж', L':'}, {L'Э', L'\"'},
    {L'Я', L'Z'}, {L'Ч', L'X'}, {L'С', L'C'}, {L'М', L'V'}, {L'И', L'B'}, {L'Т', L'N'}, {L'Ь', L'M'}, {L'Б', L'<'}, {L'Ю', L'>'},
    {L'Ї', L'}'}, // Unique to Ukrainian uppercase
    {L'Є', L'\"'} // Unique to Ukrainian uppercase
};


// Function to get the current date as a formatted string
std::wstring GetCurrentDate(const wchar_t* pattern) {
    std::time_t now = std::time(nullptr);
    std::tm localTime;
    localtime_s(&localTime, &now);
    std::wostringstream dateStream;
    dateStream << std::put_time(&localTime, pattern); // Format
    return dateStream.str();
}

void RegisterPasswordFilterEventSource(HMODULE hModule) {
    std::wstring basePath = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\";
    std::wstring fullPath = basePath + PROVIDER_NAME; // Concatenate the base path with the source name
    HKEY hKey;
    // Create or open the registry key for the event source.
    LONG result = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        fullPath.c_str(),
        0,
        nullptr,
        0,
        KEY_WRITE,
        nullptr,
        &hKey,
        nullptr
    );

    if (result == ERROR_SUCCESS) {
        // Get the path of the current DLL
        wchar_t path[MAX_PATH];
        DWORD typesSupported = EVENTLOG_INFORMATION_TYPE | EVENTLOG_ERROR_TYPE;

        GetModuleFileNameW(hModule, path, MAX_PATH); // Get the full path of this DLL

        // Set the EventMessageFile value (DLL or executable path)
        RegSetValueEx(hKey, L"EventMessageFile", 0, REG_SZ, (const BYTE*)path, (wcslen(path) + 1) * sizeof(wchar_t));
        RegSetValueEx(hKey, L"TypesSupported", 0, REG_DWORD, (const BYTE*)&typesSupported, sizeof(typesSupported));
        // Close the key
        RegCloseKey(hKey);
        //std::wcout << L"Event source registered successfully." << std::endl;
    } else {
        //std::wcerr << L"Failed to register event source. Error: " << GetLastError() << std::endl;
    }
}


// Function to rotate the log file
void RotateLogFile() {
    std::lock_guard<std::mutex> guard(logMutex); // Ensure thread safety
    
    std::ifstream currentLogFile(LOG_FILE, std::ios::ate | std::ios::binary); // Check the size of the current log file
    if ( !currentLogFile.is_open() ) return; //cant open
    size_t currentSize = currentLogFile.tellg(); //get size
    if (currentSize < MAX_LOG_SIZE) return; //check size

    //do rename...
    currentLogFile.close();  //close before rename
    std::wstring newLogName = std::wstring(LOG_FILE) + L"." + GetCurrentDate(ROTATE_FILENAME_SUFIX); // Create the new log file name with the current date
            
    if (_wrename(LOG_FILE, newLogName.c_str()) != 0) { // Rename the old log file
        //OutputDebugStringW(L"Failed to rename log file.\n");
    } else {
        // Create a new empty log file
        std::wofstream newLogFile(LOG_FILE, std::ios::trunc);
        newLogFile.close();
    }
}


void LogMessage(const std::wstring& message) {

    RotateLogFile(); // Check for log rotation before logging

    std::lock_guard<std::mutex> guard(logMutex); // Automatically locks and unlocks the mutex

    // Open log file in append mode
    std::wofstream logFile(LOG_FILE, std::ios_base::app);
    if (logFile.is_open()) {
        std::wstring event = GetCurrentDate(LOG_DATETIME_FORMAT) + L" " + message + L"\n";
        //logFile << GetCurrentDate(LOG_DATETIME_FORMAT) << L" - " << message << std::endl; // Write formatted message to the log
        logFile << event;
        logFile.close(); // Close the log file
    } else {
        //OutputDebugStringW(L"Failed to open log file.\n"); // Note the 'W' to use the wide version
    }
}

//helper func
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

//convert UA to EN and lowercase password
PUNICODE_STRING standardizePassword(PUNICODE_STRING input) {
    ULONG inputLength = input->Length / sizeof(WCHAR);
    std::wstring standardizedPassword;
    standardizedPassword.reserve(inputLength); // Reserve space for efficiency

    // Standardize input
    for (ULONG i = 0; i < inputLength; i++) {
        wchar_t c = input->Buffer[i];
        // Map RU to EN
        if (combinedMap.find(c) != combinedMap.end()) {
            c = combinedMap[c];
            LogMessage(L"Converted: " + std::wstring(1, input->Buffer[i])  + L" to " + std::wstring(1, c));
        } 
        standardizedPassword += c; // Append character
    }

    // Convert to lowercase after mapping
    std::wstring lowerCasePassword;
    for (wchar_t ch : standardizedPassword) {
        wchar_t lowerCh = towlower(ch); // Convert to lowercase using towlower
        lowerCasePassword += lowerCh;
    }
    PUNICODE_STRING output = CreateUnicodeString(lowerCasePassword);
	SecureZeroMemory(input->Buffer, input->Length);
	standardizedPassword.clear();
	lowerCasePassword.clear();
    return output;
}

std::vector<std::wstring> loadRestrictedPatterns(const wchar_t* filename) {
    std::lock_guard<std::mutex> lock(patternMutex); // Lock the mutex

    HANDLE hEventLog = NULL; //event log handler
    hEventLog = RegisterEventSource(NULL, PROVIDER_NAME);
    auto currentWriteTime = std::filesystem::last_write_time(filename);
    if (restrictedPatterns.empty() || currentWriteTime != lastWriteTime) { // Check if we need to reload pattern file
        restrictedPatterns.clear(); // Clear existing patterns

        std::wifstream file(filename); // Open the file
        if (file.is_open()) {
            std::wstring line;
            while (std::getline(file, line)) {
                size_t length = line.length();
                if (!line.empty() && length <= MAX_PATTERN_LENGTH && length >= MIN_PATTERN_LENGTH) {
                    restrictedPatterns.push_back(line); // Add valid patterns
                }
            }
            file.close();
            lastWriteTime = currentWriteTime; // Update the last write time
            //LogMessage(L"Pattern file reloaded successfully.");
            LPCWSTR pInsertStrings[1] = { NULL };
            std::wstring sizeString = std::to_wstring(restrictedPatterns.size());
            pInsertStrings[0] = sizeString.c_str();

            if (NULL == hEventLog) {
                LogMessage(L"Pattern file reloaded successfully. Loaded Patterns:" + sizeString);
            } else {
                ReportEvent(hEventLog, EVENTLOG_INFORMATION_TYPE, PASSWORD_FILTER_EVENTS, PATTERN_RELOADED, NULL, 1, 0, (LPCWSTR*)pInsertStrings, NULL);
            }
        } else {
            if (NULL == hEventLog) {
                LogMessage(L"Failed to open  pattern file. Loading defaults.");
            } else {
                ReportEvent(hEventLog, EVENTLOG_ERROR_TYPE , PASSWORD_FILTER_EVENTS, PATTERN_ERROR, NULL, 0, 0, NULL, NULL);
            }
            //LogMessage(L"Failed to open restricted patterns file. Loading defaults.");
            restrictedPatterns.push_back(L"1234567890"); // Default pattern
        }
    }
    DeregisterEventSource(hEventLog);
    return restrictedPatterns; 
}


size_t validateNewPasswordPattern(PUNICODE_STRING NewPassword) {
    //return index of pattern item or 0
    size_t result = 0;
    std::vector<std::wstring> restrictedPatterns = loadRestrictedPatterns(PATTERN_FILE);
    
    // Check against restricted patterns
    for (std::size_t index = 0; index < restrictedPatterns.size(); ++index) {
        const auto& pattern = restrictedPatterns[index];
        if (wcsstr(NewPassword->Buffer, pattern.c_str()) != NULL) {
            result = index;
            break;
        }
    }
    // Perform secure erase of the password
    SecureZeroMemory(NewPassword->Buffer, NewPassword->Length);
    return result; // Or FALSE based on your checks
}


extern "C" __declspec(dllexport) BOOLEAN WINAPI PasswordFilter(
    PUNICODE_STRING AccountName,
    PUNICODE_STRING FullName,
    PUNICODE_STRING Password,
    BOOLEAN SetOperation
)
{
    //result var
    BOOLEAN result = TRUE;

    // Create std::wstring from AccountName->Buffer
    std::wstring accountNameString(AccountName->Buffer, AccountName->Length / sizeof(wchar_t));
    std::wstring fullNameString(FullName->Buffer, FullName->Length / sizeof(wchar_t));

    size_t validateResult = 0;
    if (Password != NULL && Password->Buffer != NULL) {
        validateResult = validateNewPasswordPattern(standardizePassword(Password)); //validate and lowercased and change layout password
        SecureZeroMemory(Password->Buffer, Password->Length);
    }

    if (validateResult == 0)  { // Password is valid
        result = TRUE; 
    } else {
        LPCWSTR pInsertStrings[3] = { NULL, NULL, NULL };
        const auto& pattern = restrictedPatterns[validateResult]; 
        pInsertStrings[0] = accountNameString.c_str();
        pInsertStrings[1] = fullNameString.c_str();
        pInsertStrings[2] = pattern.c_str();
        HANDLE hEventLog = NULL; //event log handler
        hEventLog = RegisterEventSource(NULL, PROVIDER_NAME);
        if (NULL == hEventLog) {
            LogMessage(L"Password didn't pass the filter.  AccountName:" + accountNameString + L", FullName:" + fullNameString + L", Pattern:" + pattern);
        } else {
            ReportEvent(hEventLog, EVENTLOG_WARNING_TYPE, PASSWORD_FILTER_EVENTS, PATTERN_FILTER, NULL, 3, 0, (LPCWSTR*)pInsertStrings, NULL);
        }
        DeregisterEventSource(hEventLog);
        result = FALSE; // Password is invalid
    }
    
    return result;
    
}




// Default DllMain implementation
BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        std::locale::global(std::locale(""));
        RegisterPasswordFilterEventSource(static_cast<HMODULE>(hModule));
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE; // Successful initialization
}

//const double   PASSWORD_THRESHOLD_SIMILARITY = 0.7; // Similarity threshold for password changes
// BOOL validateOldToNewPasswordPattern(PUNICODE_STRING NewPassword, PUNICODE_STRING OldPassword) {
//     //prepare result
//     bool result = TRUE;

//     // Get lengths of old and new passwords
//     size_t oldLength = OldPassword->Length / sizeof(WCHAR);
//     size_t newLength = NewPassword->Length / sizeof(WCHAR);

//     // Count character frequencies for old and new passwords
//     std::unordered_map<wchar_t, int> oldPasswordFreq;
//     std::unordered_map<wchar_t, int> newPasswordFreq;

//     // Count frequencies for each character in both passwords
//     for (size_t i = 0; i < min(oldLength, newLength); ++i) {
//         oldPasswordFreq[OldPassword->Buffer[i]]++; // Count characters in old password
//         newPasswordFreq[NewPassword->Buffer[i]]++; // Count characters in new password
//     }

//     // Compare frequencies and calculate the number of matching symbols
//     int sameSymbolsCount = 0;
//     int totalOldSymbolsCount = 0;

//     for (const auto& entry : oldPasswordFreq) {
//         wchar_t charSymbol = entry.first; // Character to compare
//         int oldCount = entry.second; // Count in old password
//         int newCount = newPasswordFreq[charSymbol]; // Count in new password

//         // Count matching symbols
//         sameSymbolsCount += min(oldCount, newCount); // Only count the minimum occurrence
//         totalOldSymbolsCount += oldCount; // Count all occurrences in the old password
//     }

//     // Calculate the similarity percentage
//     double similarityPercentage = (static_cast<double>(sameSymbolsCount) / totalOldSymbolsCount);

//     if (similarityPercentage >= PASSWORD_THRESHOLD_SIMILARITY) {
//         result = FALSE; // Reject the password change if similarity threshold is exceeded
//     }

//     // Securely erase the passwords after use
//     SecureZeroMemory(NewPassword->Buffer, NewPassword->Length);
//     SecureZeroMemory(OldPassword->Buffer, OldPassword->Length);
//     return result;
// }