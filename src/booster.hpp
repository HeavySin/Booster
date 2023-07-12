//
// Created by HeavySin on 9/07/2023.
//

#ifndef BOOSTER_HPP
#define BOOSTER_HPP

// GENERIC_CPP_LIB
#include <iostream>
#include <filesystem>
#include <sys/stat.h>

// Streams
#include <fstream>

// Third-Party
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#if defined(_POSIX_) || defined(__linux__)
#define PLATFORM_POSIX
#define MAX_USERNAME_LENGTH 32
const char PATH_DELIMITER{'/'};
#include <unistd.h>
#include <pwd.h>

#elif defined(_WIN32) || defined(_WIN64)
#define PLATFORM_WINDOWS
#define MAX_USERNAME_LENGTH 256
const char PATH_DELIMITER{'\\'};
#include <Windows.h>

#else
#endif


namespace IOManipulators {
    namespace FileManipulators {
        namespace Existence {
            inline bool CheckExistence0(const std::string &fileName_arg) {
                std::ifstream f(fileName_arg.c_str());
                return f.good();
            }

            inline bool CheckExistence1(const std::string &fileName_arg) {
                if (FILE *file = std::fopen(fileName_arg.c_str(), "r")) {
                    fclose(file);
                    return true;
                } else {
                    return false;
                }
            }

            inline bool CheckExistence2(const std::string &fileName_arg) {
                return (access(fileName_arg.c_str(), F_OK) != -1);
            }

            inline bool CheckExistence3(const std::string &fileName_arg) {
                struct stat buffer;
                return (stat(fileName_arg.c_str(), &buffer) == 0);
            }

            inline bool CheckExistence4(const std::string &fileName_arg) {
                return std::filesystem::exists(fileName_arg);
            }

            bool MoveAndRenameFile(const std::string srcPath_arg, const std::string dstPath_arg) {
                try {
                    std::filesystem::rename("./Gu", "../Gu");
                    return true;
                } catch (std::filesystem::filesystem_error &filesystemError) {
                    return false;
                }
            }
        }

        namespace Paths {
            std::string MakeAbsolutPath(const std::string &filePath_arg = __FILE__) {
                return std::filesystem::absolute(filePath_arg).string();
            }

            std::string MakePath(const std::string &fileName_arg) {

                return std::filesystem::current_path().string() + PATH_DELIMITER + fileName_arg;
            }

            std::string GetCanonicalPath(const std::string &filePath_arg = __FILE__) {
                return std::filesystem::canonical(filePath_arg).string();
            }

            std::string GetCurrentPath(void) {
                return std::filesystem::current_path().string();
            }

#ifdef PLATFORM_WINDOWS

            std::string GetCurrentFullPath(void) {
                char currentFullPath[MAX_PATH];
                GetModuleFileName(NULL, currentFullPath, MAX_PATH);
                return currentFullPath;
            }

#endif /* IOManipulators::FileManipulators::Paths -> GetCurrentFullPath - [PLATFORM_WINDOWS] */

        }
    }

    std::string ReadFromFile(const std::string &fileName_arg) {
        if (IOManipulators::FileManipulators::Existence::CheckExistence4(fileName_arg)) {
            std::ifstream file(fileName_arg, std::ios::in);
            if (file.is_open()) {
                std::string fileDataHolder;
                file >> fileDataHolder;
                file.close();
                return fileDataHolder;
            }
        }
        return "DOES_NOT_EXISTS";
    }

    bool WriteToFile(const std::string &fileName_arg, std::string data_arg = "", bool asAppend = false,
                     bool asBinary_arg = false) {
        std::ofstream file(fileName_arg, std::ios::out);
        if (file.is_open()) {
            file << data_arg;
            file.close();
            return true;
        } else {
            return false;
        }
    }
}


namespace CLI {
    void ConsoleOut(const std::basic_string<char> input_arg) {
        std::cout << input_arg << std::endl;
    }
}

namespace StringManipulators {

    namespace replace {
        void replaceAll(std::string &source, const std::string &from, const std::string &to = "") {
            std::string newString;
            newString.reserve(source.length());  // avoids a few memory allocations

            std::string::size_type lastPos = 0;
            std::string::size_type findPos;

            while (std::string::npos != (findPos = source.find(from, lastPos))) {
                newString.append(source, lastPos, findPos - lastPos);
                newString += to;
                lastPos = findPos + from.length();
            }

            // Care for the rest after last occurrence
            newString += source.substr(lastPos);

            source.swap(newString);
        }
    }

    namespace trim {

        // trim from left
        inline std::string &ltrim(std::string &s, const char *t = " \t\n\r\f\v") {
            s.erase(0, s.find_first_not_of(t));
            return s;
        }

        // trim from right
        inline std::string &rtrim(std::string &s, const char *t = " \t\n\r\f\v") {
            s.erase(s.find_last_not_of(t) + 1);
            return s;
        }

        // trim from left & right
        inline std::string &trim(std::string &s, const char *t = " \t\n\r\f\v") {
            return ltrim(rtrim(s, t), t);
        }

        // copying versions
        inline std::string ltrim_copy(std::string s, const char *t = " \t\n\r\f\v") {
            return ltrim(s, t);
        }

        inline std::string rtrim_copy(std::string s, const char *t = " \t\n\r\f\v") {
            return rtrim(s, t);
        }

        inline std::string trim_copy(std::string s, const char *t = " \t\n\r\f\v") {
            return trim(s, t);
        }
    }
}

namespace System {
#ifdef PLATFORM_WINDOWS

    std::string GetLastErrorAsString(void) {
        DWORD lastErrorCode = GetLastError();
        if (lastErrorCode == 0) {
            return "NO_ERROR";
        }
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, lastErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) &messageBuffer, 0, NULL);
        std::string message(messageBuffer, size);
        LocalFree(messageBuffer);
        return message;
    }

#endif /* System -> GetLastErrorAsString - [PLATFORM_WINDOWS] */


    namespace Users {
        std::string UsernameGetter0(void) {
#ifdef PLATFORM_POSIX
            uid_t userid;
            struct passwd* pwd;
            userid = getuid();
            pwd = getpwuid(userid);
            return pwd->pw_name;
#elifdef PLATFORM_WINDOWS
            char szBuffer[MAX_USERNAME_LENGTH];
            DWORD len = MAX_USERNAME_LENGTH;
            if (GetUserName(szBuffer, &len))
                return szBuffer;
#else
            return getenv("username");
#endif
        }

        std::string UsernameGetter1(void) {
            return getenv("username");
        }
    }

    namespace Paths {
#ifdef PLATFORM_WINDOWS

        std::string GetAppDataDirectory0(const std::string &username_arg = System::Users::UsernameGetter0()) {
            return "C:\\Users\\" + username_arg + "\\AppData\\Roaming";
        }

        std::string GetAppDataDirectory1(void) {
            return getenv("APPDATA");
        }

        std::string GetAppDataDirectory2(void) {
            return std::filesystem::temp_directory_path().parent_path().parent_path().string();
        }

#endif /* IOManipulators::FileManipulators::Paths -> GetAppDataDirectoryX - [PLATFORM_WINDOWS] */

    }

    namespace Handlers {
#ifdef PLATFORM_WINDOWS

        bool checkForFileHandle(const void *fileHandle_arg, bool shutErrors_arg = true) {
            if (fileHandle_arg == INVALID_HANDLE_VALUE) {
                if (!shutErrors_arg)
                    CLI::ConsoleOut("Failed to open the HANDLE drive: " + std::string(System::GetLastErrorAsString()));
                return false;
            } else {
                return true;
            }
        }

        bool checkForDiskGeometry(const DISK_GEOMETRY &diskGeometry_arg, bool onlyBytesPerSectorCheck = false) {
            if (onlyBytesPerSectorCheck) {
                return diskGeometry_arg.BytesPerSector > 0;
            } else {
                if (diskGeometry_arg.Cylinders.QuadPart > 0 &&
                    diskGeometry_arg.TracksPerCylinder > 0 && diskGeometry_arg.SectorsPerTrack > 0 &&
                    diskGeometry_arg.BytesPerSector > 0) {
                    return true;
                } else {
                    return false;
                }
            }
        }

#endif /* System::Handlers -> checkForFileHandle : checkForDiskGeometry : GetDeviceBytesPerSector - [PLATFORM_WINDOWS]  */

    }

    std::string ExecuteCommand(const std::string &command_arg, const short int bufferSize_arg = 128) {
        FILE *pipe = popen(command_arg.c_str(), "r");
        if (!pipe) {
            std::cerr << "Error executing command." << std::endl;
            return "<null>";
        }

        const short int bufferSize = bufferSize_arg;
        char charBuffer[bufferSize];
        std::string stringBuffer;
        while (fgets(charBuffer, bufferSize, pipe) != nullptr) {
            stringBuffer.append(charBuffer);
        }
        pclose(pipe);

        return stringBuffer;
    }

#ifdef PLATFORM_WINDOWS

    void *CreateFileRW(const std::string &fileName_arg) {
//        if (fileName_arg.ends_with("\\\\"))
        return CreateFile(fileName_arg.c_str(), (GENERIC_READ | GENERIC_WRITE), FILE_SHARE_WRITE | FILE_SHARE_READ,
                          NULL,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }

    std::pair<bool, DISK_GEOMETRY> GetDiskGeometry(void *fileHandle_arg) {
        DISK_GEOMETRY diskGeometry;
        DWORD bytesReturned;

        bool state = DeviceIoControl(
                fileHandle_arg,
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                NULL,
                0,
                &diskGeometry,
                sizeof(DISK_GEOMETRY),
                &bytesReturned,
                NULL
        );
        return {state, diskGeometry};
    }

    uint32_t GetDeviceBytesPerSector(DISK_GEOMETRY diskGeometry_arg) {
        uint32_t BytesPerSectorHolder{512};
        if (!System::Handlers::checkForDiskGeometry(diskGeometry_arg)) {
            if (!System::Handlers::checkForDiskGeometry(diskGeometry_arg, true)) {
                BytesPerSectorHolder = 512;
            }
        } else {
            BytesPerSectorHolder = diskGeometry_arg.BytesPerSector;
        }
        return BytesPerSectorHolder;
    }

#endif /* System -> CreateFileRW : GetDiskGeometry : GetDeviceBytesPerSector - [PLATFORM_WINDOWS]  */

}

namespace JsonManipulators {
    rapidjson::Document JsonParse(std::string rawJsonString_arg) {
        rapidjson::Document jsonDocTemp;
        jsonDocTemp.Parse(rawJsonString_arg.c_str());
        return jsonDocTemp;
    }

    rapidjson::StringBuffer JsonDocumentToJsonStringBuffer(rapidjson::Document &jsonDocument_arg) {
        rapidjson::StringBuffer stringBuffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(stringBuffer);
        jsonDocument_arg.Accept(writer);
        return stringBuffer;
    }
}


#ifdef PLATFORM_WINDOWS
namespace RegistryManipulators {
    namespace Paths {
        namespace Startup {
            std::string StartupAlways{R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Run)"};
            std::string StartupOnce{R"(SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce)"};
        }
    }
    namespace _internal {
        const std::string defaultRegistryItemContainerPath_arg{"Control Panel\\Keyboard\\_internal"};
        const std::string powershellExecutionCommand{
                "powershell.exe -command"};
        const std::string powershellSilentlyContinueErrorActionCommand{"-ErrorAction SilentlyContinue"};
        const std::string ERROR_PREFIX{"[ERROR]"};
        const std::string SUCCESS_PREFIX{"[SUCCESSFUL]"};
        const std::string ERROR_RETURN{"<error>"};
        const std::string powershellCheckForErrorCommand{
                "if (-not $?) {Write-Host \'" + ERROR_PREFIX + "\' $Error[0].ToString();}"};

        const std::string powershellCheckForErrorAndSuccess{
                "if(-not $?){Write-Host \'" + ERROR_PREFIX + "\' $Error[0].ToString();}else{Write-Host \'" +
                SUCCESS_PREFIX + "\';}"
        };

        const std::string powershellEOFCommand{
                powershellSilentlyContinueErrorActionCommand + ';' + powershellCheckForErrorCommand + '"'};

        const std::string powershellEOFWithSuccessFlagCommand{
                powershellSilentlyContinueErrorActionCommand + ';' + powershellCheckForErrorAndSuccess + '"'};

        enum registryEntries : uint8_t {
            HKEY_CURRENT_USER_ = 0,
            HKEY_LOCAL_MACHINE_ = 1

        };

        enum registryPropertyTypes : uint8_t {
            String = 0,
            ExpandString,
            MultiString,
            DWord,
            QWord,
            Binary,
            Unknown,
        };

        std::string registryEntrySetter(registryEntries registryEntry = registryEntries::HKEY_CURRENT_USER_) {
            switch (registryEntry) {
                case registryEntries::HKEY_CURRENT_USER_:
                    return "HKCU:\\";
                case registryEntries::HKEY_LOCAL_MACHINE_:
                    return "HKLM:\\";
                default:
                    return "HKLM:\\";
            }
        }


        std::string
        registryPropertyTypeSetter(registryPropertyTypes registryPropertyType = registryPropertyTypes::String) {
            switch (registryPropertyType) {
                case registryPropertyTypes::String:
                    return "String";
                case registryPropertyTypes::ExpandString:
                    return "ExpandString";
                case registryPropertyTypes::MultiString:
                    return "MultiString";
                case registryPropertyTypes::DWord:
                    return "DWord";
                case registryPropertyTypes::QWord:
                    return "QWord";
                case registryPropertyTypes::Binary:
                    return "Binary";
                case registryPropertyTypes::Unknown:
                    return "Unknown";
                default:
                    return "String";
            }
        }


        inline bool CheckForError(std::string &commandOutput_arg) {
            return commandOutput_arg.contains(ERROR_PREFIX);
        }

        inline bool CheckForSuccess(std::string &commandOutput_arg) {
            return commandOutput_arg.contains(SUCCESS_PREFIX);
        }
    }

    namespace WinAPI {
        bool SetOrEditItemPropertyValue(const std::string &registryItemPropertyNewValue_arg,
                                        const std::string &registryItemPropertyName_arg,
                                        const std::string &registryItemContainerPath_arg = _internal::defaultRegistryItemContainerPath_arg,
                                        HKEY hKey_arg = HKEY_CURRENT_USER) {
            HKEY hKey;
            LONG lnRes = RegOpenKeyEx(hKey_arg,
                                      registryItemContainerPath_arg.c_str(),
                                      0, KEY_WRITE,
                                      &hKey);
            if (ERROR_SUCCESS == lnRes) {
                lnRes = RegSetValueEx(hKey,
                                      registryItemPropertyName_arg.c_str(),
                                      0,
                                      REG_SZ,
                                      (unsigned char *) registryItemPropertyNewValue_arg.c_str(),
                                      registryItemPropertyNewValue_arg.size());
                RegCloseKey(hKey);
                return true;
            }

            RegCloseKey(hKey);
            return false;

        }

        bool AddProgramToStartup(const std::string &programPath_arg, const std::string &programName_arg = "001",
                                 HKEY hKey_arg = HKEY_CURRENT_USER) {
            return RegistryManipulators::WinAPI::SetOrEditItemPropertyValue(programPath_arg, programName_arg,
                                                                            RegistryManipulators::Paths::Startup::StartupAlways,
                                                                            hKey_arg);
        }
    }


    // ---------------------------- [ContainerManipulators] ----------------------------


    template<_internal::registryEntries registryEntry = _internal::registryEntries::HKEY_CURRENT_USER_>
    bool
    checkForItemContainerExistence(
            std::string registryItemContainerPath_arg = _internal::defaultRegistryItemContainerPath_arg) {
        const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPath_arg};


        std::string commandTemp{
                _internal::powershellExecutionCommand + " \"Test-Path -Path '" + fullPath + "' " +
                _internal::powershellEOFWithSuccessFlagCommand};

        std::string commandResult = System::ExecuteCommand(commandTemp);


        if (_internal::CheckForSuccess(commandResult)) {
            if (commandResult.contains("True")) {
                return true;
            } else if (commandResult.contains("False")) {
                return false;
            } else {
                return true;
            }
        } else {
            return false;
        }
    }

    template<_internal::registryEntries registryEntry = _internal::registryEntries::HKEY_CURRENT_USER_>
    std::string
    GetItemContainer(std::string registryItemContainerPath_arg = _internal::defaultRegistryItemContainerPath_arg) {
        if (checkForItemContainerExistence(registryItemContainerPath_arg)) {
            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPath_arg};

            std::string commandTemp{
                    _internal::powershellExecutionCommand + " \"Get-ItemProperty -Path '" + fullPath + "' " +
                    _internal::powershellEOFCommand};

            std::string commandResult = System::ExecuteCommand(commandTemp);

            if (_internal::CheckForError(commandResult)) {
                return commandResult;
            } else {
                return commandResult;
            }
        } else {
            return "DOES_NOT_EXISTS";
        }
    }

    template<_internal::registryEntries registryEntry = _internal::registryEntries::HKEY_CURRENT_USER_>
    std::string NewItemContainer(std::string registryItemContainerName_arg,
                                 std::string registryItemContainerPath_arg = "Control Panel\\Keyboard") {

        if (!checkForItemContainerExistence(
                registryItemContainerPath_arg + '\\' + registryItemContainerName_arg)) {
            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPath_arg};

            std::string commandTemp{
                    _internal::powershellExecutionCommand + " \"New-Item -Path '" + fullPath +
                    "' -Name '" + registryItemContainerName_arg +
                    "' " + _internal::powershellEOFCommand};

            std::string commandResult = System::ExecuteCommand(commandTemp);

            if (_internal::CheckForError(commandResult)) {
                return commandResult;
            } else {
                return commandResult;
            }
        } else {
            return "ALREADY_EXISTS";
        }
    }


    template<_internal::registryEntries registryEntry = _internal::registryEntries::HKEY_CURRENT_USER_>
    std::string RemoveSubContainersInsideItemContainer(
            std::string registryItemContainerPath_arg = _internal::defaultRegistryItemContainerPath_arg) {

        if (checkForItemContainerExistence(registryItemContainerPath_arg)) {
            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPath_arg};

            std::string commandTemp{
                    _internal::powershellExecutionCommand + " \"Remove-Item -Path '" + fullPath +
                    "\\*' -Recurse "
                    + _internal::powershellEOFWithSuccessFlagCommand};

            std::string commandResult = System::ExecuteCommand(commandTemp);

            std::cout << commandTemp << std::endl;

            if (_internal::CheckForSuccess(commandResult)) {
                return commandResult;
            } else {
                return commandResult;
            }
        } else {
            return "PATH_DOES_NOT_EXISTS";
        }
    }

    template<_internal::registryEntries registryEntry = _internal::registryEntries::HKEY_CURRENT_USER_>
    std::string RemoveSubItemsInsideItemContainer(
            std::string registryItemContainerPath_arg = _internal::defaultRegistryItemContainerPath_arg) {

        if (checkForItemContainerExistence(registryItemContainerPath_arg)) {
            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPath_arg};

            std::string commandTemp{
                    _internal::powershellExecutionCommand + " \"Remove-ItemProperty -Path '" + fullPath +
                    "' -Name * "
                    + _internal::powershellEOFWithSuccessFlagCommand};

            std::string commandResult = System::ExecuteCommand(commandTemp);

            std::cout << commandTemp << std::endl;

            if (_internal::CheckForSuccess(commandResult)) {
                return commandResult;
            } else {
                return commandResult;
            }
        } else {
            return "PATH_DOES_NOT_EXISTS";
        }
    }

    // ---------------------------- [PropertyManipulators] ----------------------------
    template<_internal::registryEntries registryEntry = _internal::registryEntries::HKEY_CURRENT_USER_>
    std::string
    checkForItemPropertyValueExistence(std::string registryItemPropertyName_arg,
                                       std::string registryItemContainerPath_arg = _internal::defaultRegistryItemContainerPath_arg) {
        const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPath_arg};

        std::string commandTemp{
                _internal::powershellExecutionCommand + " \"Get-ItemPropertyValue -Path '" + fullPath +
                "' -Name '" +
                registryItemPropertyName_arg +
                "' " + _internal::powershellEOFWithSuccessFlagCommand};

        std::string commandResult = System::ExecuteCommand(commandTemp);

        if (_internal::CheckForSuccess(commandResult)) {
            return "DOES_EXISTS";
        } else {
            if (commandResult.contains("does not exist")) {
                if (commandResult.contains("Property")) {
                    return "PROPERTY_DOES_NOT_EXISTS";
                } else if (commandResult.contains("Cannot find path")) {
                    return "PATH_DOES_NOT_EXISTS";
                } else {
                    return commandResult;
                }
            } else {
                return commandResult;
            }
        }
    }

    template<_internal::registryEntries registryEntry = _internal::registryEntries::HKEY_CURRENT_USER_>
    std::string
    GetItemPropertyValue(std::string registryItemPropertyName_arg,
                         std::string registryItemContainerPath_arg = _internal::defaultRegistryItemContainerPath_arg) {
        std::string propertyValueState = checkForItemPropertyValueExistence(registryItemPropertyName_arg,
                                                                            registryItemContainerPath_arg);
        if (propertyValueState == "DOES_EXISTS") {
            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPath_arg};

            std::string commandTemp{
                    _internal::powershellExecutionCommand + " \"Get-ItemPropertyValue -Path '" + fullPath +
                    "' -Name '" +
                    registryItemPropertyName_arg +
                    "' " + _internal::powershellEOFCommand};

            std::string commandResult = System::ExecuteCommand(commandTemp);

            if (_internal::CheckForError(commandResult)) {
                return _internal::ERROR_RETURN;
            } else {
                return commandResult;
            }
        } else {
            return propertyValueState;
        }
    }

    template<_internal::registryEntries registryEntry = _internal::registryEntries::HKEY_CURRENT_USER_>
    std::string
    SetOrEditItemPropertyValue(std::string registryItemPropertyNewValue_arg, std::string registryItemPropertyName_arg,
                               std::string registryItemContainerPath_arg = _internal::defaultRegistryItemContainerPath_arg) {
        if (checkForItemContainerExistence(registryItemContainerPath_arg)) {

            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPath_arg};

            std::string commandTemp{
                    _internal::powershellExecutionCommand + " \"Set-ItemProperty -Path '" + fullPath +
                    "' -Name '" + registryItemPropertyName_arg +
                    "' -Value '" + registryItemPropertyNewValue_arg +
                    "' " + _internal::powershellEOFWithSuccessFlagCommand};


            std::string commandResult = System::ExecuteCommand(commandTemp);


            if (_internal::CheckForSuccess(commandResult)) {
                return commandResult;
            } else {
                return commandResult;
            }
        } else { return "PATH_DOES_NOT_EXISTS"; }
    }

    template<_internal::registryPropertyTypes registryPropertyType = _internal::registryPropertyTypes::String, _internal::registryEntries registryEntry = _internal::registryEntries::HKEY_CURRENT_USER_>
    std::string
    NewItemPropertyValue(std::string registryItemPropertyValue_arg, std::string registryItemPropertyName_arg,
                         std::string registryItemContainerPath_arg = _internal::defaultRegistryItemContainerPath_arg) {
        std::string itemPropertyState = checkForItemPropertyValueExistence(registryItemPropertyName_arg,
                                                                           registryItemContainerPath_arg);

        if (checkForItemContainerExistence(registryItemContainerPath_arg)) {
            if (itemPropertyState != "DOES_EXISTS") {

                const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPath_arg};
                const std::string propertyType{registryPropertyTypeSetter(registryPropertyType)};

                std::string commandTemp{
                        _internal::powershellExecutionCommand + " \"New-ItemProperty -Path '" + fullPath +
                        "' -Name '" + registryItemPropertyName_arg +
                        "' -Value '" + registryItemPropertyValue_arg +
                        "' -PropertyType '" + propertyType + "'"
                        + _internal::powershellEOFWithSuccessFlagCommand};

                std::string commandResult = System::ExecuteCommand(commandTemp);

                if (_internal::CheckForSuccess(commandResult)) {
                    return commandResult;
                } else {
                    return commandResult;
                }
            } else if (itemPropertyState == "DOES_EXISTS") {
                return "PROPERTY_ALREADY_EXISTS";
            } else {
                return itemPropertyState;
            }
        } else {
            return "PATH_DOES_NOT_EXISTS";
        }
    }

    template<_internal::registryEntries registryEntry = _internal::registryEntries::HKEY_CURRENT_USER_>
    std::string RemoveItemPropertyValue(std::string registryItemPropertyName_arg,
                                        std::string registryItemContainerPath_arg = _internal::defaultRegistryItemContainerPath_arg) {
        std::string itemPropertyState = checkForItemPropertyValueExistence(registryItemPropertyName_arg,
                                                                           registryItemContainerPath_arg);
        if (itemPropertyState == "DOES_EXISTS") {
            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPath_arg};

            std::string commandTemp{
                    _internal::powershellExecutionCommand + " \"Remove-ItemProperty -Path '" + fullPath +
                    "' -Name '" +
                    registryItemPropertyName_arg + "'\""};

            std::string commandResult = System::ExecuteCommand(commandTemp);

            if (_internal::CheckForSuccess(commandResult)) {
                return commandResult;
            } else {
                return commandResult;
            }
        } else {
            return itemPropertyState;
        }
    }
}
#endif /* RegistryManipulators - [PLATFORM_WINDOWS]  */


#endif //BOOSTER_HPP
