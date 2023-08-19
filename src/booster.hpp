#ifndef BOOSTER_HPP
#define BOOSTER_HPP

#include <filesystem>
#include <algorithm>
#include <random>
#include <exception>
#include <iostream>
#include <ranges>
#include <limits>
#include <cmath>
#include <fcntl.h>
#include <sys/stat.h>

// STL
#include <vector>

// Streams
#include <fstream>
#include <sstream>

// Third-Party
#include <rapidjson/schema.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#if defined(_POSIX_) || defined(__linux__)
#define PLATFORM_POSIX
#define MAX_USERNAME_LENGTH 32
const char PATH_DELIMITER{'/'};
const char FLUSH_TERMINAL[] = "clear";

#include <unistd.h>
#include <pwd.h>

#elif defined(_WIN32) || defined(_WIN64)
#define PLATFORM_WINDOWS
#define MAX_USERNAME_LENGTH 256
const char PATH_DELIMITER{'\\'};
const char FLUSH_TERMINAL[] = "cls";

#include <Windows.h>

#else
#endif

namespace Booster {
    namespace BoosterException {
        // Additional Exception type for handling both function return type and error handling
//    template<typename T1 /* Function ReturnType */, typename T2 /* ErrorException */>
//    class ExceptionContainer : public std::pair<T1, T2> {
//    public:
//        std::pair<T1, T2> _pair;
//    };

        class InputOutput {
        public:
            enum InputOutputException {
                Success,
                OperationFailed,
                FileNotFound,
                AccessDenied,
                InvalidHandler,
                FailedToSetFilePointer,
                FailedToGetFileSize,
                FailedToWrite,
                FailedToRead,
            };

            InputOutputException exception;

            explicit InputOutput(InputOutputException exceptionArg) : exception(exceptionArg) {}
        };
    }

    namespace System {
        bool exec(const char commandArg[]) {
            return system(commandArg);
        }
    }

    namespace Getters {
        std::string ReadLine(const std::string &placeholderArg = "") {
            std::string retrievedLineHolder;
            std::cout << placeholderArg << std::flush;
            if (!getline(std::cin, retrievedLineHolder)) {
                return "<error>";
            }
            return retrievedLineHolder;
        }

        char ReadChar(void) {
            char tempChar;
            std::cin.get(tempChar);
            return tempChar;
        }
    }

    namespace CLI {
        void ConsoleOut(const std::basic_string<char> &inputMessageArg) {
            std::cout << inputMessageArg << std::endl;
        }

        void ConsoleOutFlush(const std::string &inputMessageArg) {
            std::cout << inputMessageArg << std::flush;
        }

        namespace Halts {
            std::string haltDefaultMessage{"Press enter to continue..."};

            void
            PressXTo0(const char &pressXArg = '\n',
                      const std::string &haltMessageArg = CLI::Halts::haltDefaultMessage) {
                CLI::ConsoleOutFlush(haltMessageArg);
                while (Getters::ReadChar() != pressXArg);
            }

            void
            PressXTo1(const char &pressXArg = '\n',
                      const std::string &haltMessageArg = CLI::Halts::haltDefaultMessage) {
                CLI::ConsoleOutFlush(haltMessageArg);
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), pressXArg);
            }

            void PressAnyTo(const std::string &haltMessageArg = CLI::Halts::haltDefaultMessage) {
                CLI::ConsoleOutFlush(haltMessageArg);
                std::cin.ignore();
            }

            void PressEnterTo(const std::string &haltActionMessageArg = "continue...") {
                PressAnyTo("\nPress Enter to " + haltActionMessageArg);
            }
        }

        namespace Manipulators {
            namespace Screen {
                void FlushScreen0(void) {
                    std::cout << "\033[2J\033[1;1H" << std::endl;
                }

                void FlushScreen1(void) {
                    System::exec(FLUSH_TERMINAL);
                }
            }
        }

        void PrintTitle(const std::string &titleMessageArg,
                        bool titleBottomPaddingArg = true,
                        const std::string &titleCharArg = "-",
                        bool titleSpaceArg = true,
                        bool flushScreenArg = true,
                        uint8_t titleDiameterArg = 18) {
            if (flushScreenArg) {
                CLI::Manipulators::Screen::FlushScreen1();
            }
            std::string titleSide;
            for (uint8_t titleDiameterCounter{0};
                 titleDiameterCounter <= titleDiameterArg; ++titleDiameterCounter) {
                titleSide.append(titleCharArg);
            }

            CLI::ConsoleOut(titleSide
                            + (titleSpaceArg ? " " : "")
                            + '[' + titleMessageArg + ']'
                            + (titleSpaceArg ? " " : "")
                            + titleSide);


            if (titleBottomPaddingArg) {
                CLI::ConsoleOut("\n");
            }
        }

        std::vector<int32_t> PrintTable(const std::vector<std::string> &tableItems,
                                        bool tableAtExit = true,
                                        bool tableAtBack = false,
                                        bool tableBottomPadding = true) {

            int32_t tableItemPtr{0};
            std::vector<int32_t> tableItemsRange;
            for (const std::string &tableItem: tableItems) {
                std::cout << '[' << ++tableItemPtr << ']' << ' ' << tableItem << std::endl;
                tableItemsRange.push_back(tableItemPtr);
            }
            if (tableAtExit) {
                std::cout << "[0] EXIT" << std::endl;
                tableItemsRange.push_back(0);
            }

            if (tableAtBack) {
                std::cout << '[' << ++tableItemPtr << ']' << ' ' << "BACK" << std::endl;
                tableItemsRange.push_back(tableItemPtr);
            }

            if (tableBottomPadding) {
                CLI::ConsoleOut("\n");
            }

            return tableItemsRange;
        }
    }

    namespace Generators {
        namespace Random {
            namespace strings {
                std::string
                randomNumberGen1(const uint32_t randomNumberLengthArg = 32, const bool startsWithZero = false) {
                    uint32_t randomNumberLengthTemp{randomNumberLengthArg};
                    std::string generatedNumberHolder;
                    std::random_device randomSeed;
                    std::mt19937 gen(randomSeed());
                    std::uniform_int_distribution dist(0, 9);
                    if (!startsWithZero) {
                        generatedNumberHolder += std::to_string(std::uniform_int_distribution(1, 9)(gen));
                        randomNumberLengthTemp -= 1;
                    }

                    for (int i = 0; i < randomNumberLengthTemp; ++i) {
                        generatedNumberHolder += std::to_string(dist(gen));
                    }

                    return generatedNumberHolder;
                }
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
#endif

        namespace Handlers {
#ifdef PLATFORM_WINDOWS

            bool checkForFileHandle(const void *fileHandleArg, bool shutErrorsArg = true) {
            if (fileHandleArg == INVALID_HANDLE_VALUE) {
                if (!shutErrorsArg)
                    CLI::ConsoleOut("Failed to open the HANDLE drive: " + std::string(System::GetLastErrorAsString()));
                return false;
            } else {
                return true;
            }
        }


        bool checkForDiskGeometry(const DISK_GEOMETRY &diskGeometryArg, bool onlyBytesPerSectorCheck = false) {
            if (onlyBytesPerSectorCheck) {
                return diskGeometryArg.BytesPerSector > 0;
            } else {
                if (diskGeometryArg.Cylinders.QuadPart > 0 &&
                    diskGeometryArg.TracksPerCylinder > 0 && diskGeometryArg.SectorsPerTrack > 0 &&
                    diskGeometryArg.BytesPerSector > 0) {
                    return true;
                } else {
                    return false;
                }
            }
        }

#endif /* System::Handlers -> checkForFileHandle : checkForDiskGeometry : GetDeviceBytesPerSector - [PLATFORM_WINDOWS]  */

        }

        namespace Sleeps {
            void SleepForMillisecond(const uint64_t millisecondsArg) {
#ifdef PLATFORM_WINDOWS
                Sleep(millisecondsArg);
#elif defined(PLATFORM_POSIX)
                usleep(millisecondsArg * 1000);
#endif
            }
        }
#ifdef PLATFORM_WINDOWS

        std::pair<bool, DISK_GEOMETRY> GetDiskGeometry(void *fileHandleArg, bool closeHandleArg = false) {
        DISK_GEOMETRY diskGeometry;
        DWORD bytesReturned;

        bool state = DeviceIoControl(
                fileHandleArg,
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                NULL,
                0,
                &diskGeometry,
                sizeof(DISK_GEOMETRY),
                &bytesReturned,
                NULL
        );
        if (closeHandleArg) {
            CloseHandle(fileHandleArg);
        }
        return {state, diskGeometry};
    }

    uint32_t GetDeviceBytesPerSector(DISK_GEOMETRY diskGeometryArg) {
        uint32_t BytesPerSectorHolder{512};
        if (!System::Handlers::checkForDiskGeometry(diskGeometryArg)) {
            if (!System::Handlers::checkForDiskGeometry(diskGeometryArg, true)) {
                BytesPerSectorHolder = 512;
            }
        } else {
            BytesPerSectorHolder = diskGeometryArg.BytesPerSector;
        }
        return BytesPerSectorHolder;
    }

#endif /* System -> GetLastErrorAsString - [PLATFORM_WINDOWS] */


        namespace Users {
            std::string UsernameGetter0(void) {
#ifdef PLATFORM_POSIX
                uid_t userid;
                struct passwd *pwd;
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

            std::string GetAppDataDirectory0(const std::string &usernameArg = System::Users::UsernameGetter0()) {
            return "C:\\Users\\" + usernameArg + "\\AppData\\Roaming";
        }

        std::string GetAppDataDirectory1(void) {
            return getenv("APPDATA");
        }

        std::string GetAppDataDirectory2(void) {
            return std::filesystem::temp_directory_path().parent_path().parent_path().string();
        }

#endif /* IOManipulators::FileManipulators::Paths -> GetAppDataDirectoryX - [PLATFORM_WINDOWS] */

        }

        std::string ExecuteCommand(const std::string &commandArg, const short int bufferSizeArg = 128) {
            FILE *pipe = popen(commandArg.c_str(), "r");
            if (!pipe) {
                std::cerr << "Error executing command." << std::endl;
                return "<null>";
            }

            const short int bufferSize = bufferSizeArg;
            char charBuffer[bufferSize];
            std::string stringBuffer;
            while (fgets(charBuffer, bufferSize, pipe) != nullptr) {
                stringBuffer.append(charBuffer);
            }
            pclose(pipe);

            return stringBuffer;
        }
    }

    namespace CLI {
        namespace Sleeps {
            void Countdown(uint32_t secondsArg, const std::string &countdownMessageArg) {
                for (uint64_t counter{0}; counter < secondsArg; counter++) {
                    std::cout << '\r' << countdownMessageArg << (secondsArg - counter) << " seconds."
                              << (secondsArg > 10 ? "\t\t" : "") << std::flush;
                    System::Sleeps::SleepForMillisecond(1000);

                }
                std::cout << '\r' << std::string(128, ' ') << '\r' << std::flush;
            }
        }

        void NotFound(const std::string &notFoundArg,
                      bool topPaddingArg = true,
                      bool bottomPaddingArg = false,
                      const std::string &notFoundMessageArg = "not found",
                      uint32_t sleepForMillisecondsArg = 800) {

            if (!notFoundArg.empty()) {
                CLI::ConsoleOut((topPaddingArg ? "\n\"" : "\"") + notFoundArg + "\" " + notFoundMessageArg +
                                (bottomPaddingArg ? "\n" : ""));
                System::Sleeps::SleepForMillisecond(sleepForMillisecondsArg);
            }
        }


        std::string GetCommandLineHolder(const std::string &hostnameArg,
                                         const std::string &usernameArg = System::Users::UsernameGetter0()) {
            return usernameArg + '@' + hostnameArg + " ~ $ ";
        }

        static std::string GetPanelPathHolder(const std::vector<std::string> &pathsArg) {
            std::string pathHolder;
            for (const std::string &path: pathsArg) {
                pathHolder.append(pathHolder.empty() ? "" : ">" + path);
            }
            return pathHolder;
        }
    }


    namespace STLManipulators {
        template<class C, typename T>
        bool Contains(C &&c, T e) { return std::find(std::begin(c), std::end(c), e) != std::end(c); };
    }

    namespace TypeManipulators {
        namespace EnumManipulators {
            template<typename E>
            constexpr typename std::underlying_type<E>::type to_underlying(E e) noexcept {
                return static_cast<typename std::underlying_type<E>::type>(e);
            }

            template<typename TResult, typename TInput>
            requires std::is_enum<TInput>::value
            inline constexpr TResult EnumValue(TInput enumArg) {
                return static_cast<TResult>(enumArg);
            }
        }
    }

    namespace StringManipulators {
        template<typename ... Args>
        std::string Format(const std::string &format, Args ... args) {
            int size_s = std::snprintf(nullptr, 0, format.c_str(), args ...) + 1;
            if (size_s <= 0) { throw std::runtime_error("Error during formatting."); }
            auto size = static_cast<size_t>( size_s );
            std::unique_ptr<char[]> buf(new char[size]);
            std::snprintf(buf.get(), size, format.c_str(), args ...);
            return std::string(buf.get(), buf.get() + size - 1);
        }

        namespace Convertors {
            namespace HexToText {
                std::string HexToString0(const std::string &hexArg) {
                    std::string output;
                    std::stringstream stream(hexArg);
                    stream >> std::hex;
                    while (!stream.eof()) {
                        unsigned int value;
                        stream >> value;
                        output += static_cast<char>(value);
                    }
                    return output;
                }

                std::string HexToString1(const std::string &hexArg) {
                    std::string output;
                    for (size_t i = 0; i < hexArg.length(); i += 2) {
                        std::string hexByte = hexArg.substr(i, 2);
                        unsigned char byte = static_cast<unsigned char>(std::stoi(hexByte, nullptr, 16));
                        output.push_back(byte);
                    }
                    return output;
                }

                std::string HexToString2(const std::string &hexArg) {
                    std::string output;

                    if ((output.length() % 2) != 0) {
                        return output;
                    }

                    size_t cnt = output.length() / 2;

                    for (size_t i = 0; cnt > i; ++i) {
                        uint32_t s = 0;
                        std::stringstream ss;
                        ss << std::hex << output.substr(i * 2, 2);
                        ss >> s;

                        output.push_back(static_cast<unsigned char>(s));
                    }

                    return output;
                }
            }
            namespace TextToHex {
                std::string StringToHex0(const std::string &textArg) {
                    std::stringstream stream;
                    for (char c: textArg)
                        stream << std::hex << static_cast<int>(c);
                    return stream.str();
                }

                std::string StringToHex1(const std::string &input) {
                    std::stringstream hexStream;
                    hexStream << std::hex << std::setfill('0');

                    for (char ch: input) {
                        hexStream << std::setw(2) << static_cast<unsigned char>(ch);
                    }

                    return hexStream.str();
                }

                std::string StringToHex2(const std::string &input) {
                    std::stringstream hexStream;
                    hexStream << std::hex << std::setfill('0');

                    for (char ch: input) {
                        hexStream << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(ch));
                    }

                    return hexStream.str();
                }

                uint64_t StringToNumeric(const std::string &hexString) {
                    std::istringstream converter(hexString);
                    uint64_t numericValue;

                    converter >> std::hex >> numericValue;

                    return numericValue;
                }
            }
        }

        namespace Replace {
            void ReplaceAll(std::string &source, const std::string &from, const std::string &to = "") {
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

        namespace Trim {

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

        namespace Split {
            std::vector<std::string>
            split0(const std::string &s, const std::string &delimiter, const bool removeEmptyEntries = false) {
                std::vector<std::string> tokens;

                for (size_t start = 0, end; start < s.length(); start = end + delimiter.length()) {
                    size_t position = s.find(delimiter, start);
                    end = position != std::string::npos ? position : s.length();

                    std::string token = s.substr(start, end - start);
                    if (!removeEmptyEntries || !token.empty()) {
                        tokens.push_back(token);
                    }
                }

                if (!removeEmptyEntries &&
                    (s.empty() || s.ends_with(delimiter))) {
                    tokens.emplace_back("");
                }

                return tokens;
            }
        }

        namespace Occurrence {
            uint64_t occurrence0(const std::string &textArg, const char &atCheckArg) {
                return std::count(textArg.begin(), textArg.end(), atCheckArg);
            }
        }
    }

    namespace IntManipulators {
        namespace Parsers {
            int TryParseInt0(const std::string &input) {
                try {
                    return std::stoi(input);
                } catch (std::exception &exception) {
                    return -1;
                }
            }

            bool TryParseInt1(const std::string &input, int &output) {
                try {
                    output = std::stoi(input);
                } catch (std::invalid_argument &invalidArgument) {
                    return false;
                }
                return true;
            }
        }

        namespace Rounds {
            double RoundX(double valueArg, int decimalPlacesArg = 2) {
                const double multiplier = std::pow(10.0, decimalPlacesArg);
                return std::ceil(valueArg * multiplier) / multiplier;
            }
        }


        namespace LeadingZero {
            std::string RemoveLeadingZeroPrecision(long double inputArg) {
                std::ostringstream ostringstream;
                ostringstream << inputArg;
                return ostringstream.str();
            }

            std::string AddLeadingZeroPrecision(uint64_t numArg, uint16_t leadingZerosArg) {
                return std::to_string(numArg).insert(0, leadingZerosArg, '0');
            }
        }

        namespace Convertors {
            std::string ConvertByte(int64_t bytesArg, int decimalPlacesArg = 2) {
                long gb = 1024 * 1024 * 1024;
                long mb = 1024 * 1024;
                long kb = 1024;

                std::string KB{IntManipulators::LeadingZero::RemoveLeadingZeroPrecision(
                        IntManipulators::Rounds::RoundX((double) bytesArg / kb, decimalPlacesArg))};
                std::string MB{IntManipulators::LeadingZero::RemoveLeadingZeroPrecision(
                        IntManipulators::Rounds::RoundX((double) bytesArg / mb, decimalPlacesArg))};
                std::string GB{IntManipulators::LeadingZero::RemoveLeadingZeroPrecision(
                        IntManipulators::Rounds::RoundX((double) bytesArg / gb, decimalPlacesArg))};
                if (bytesArg >= gb) {
                    return GB + " GB";
                } else if (bytesArg >= mb) {
                    return MB + " MB";
                } else if (bytesArg >= kb) {
                    return KB + " KB";
                } else { return std::to_string(bytesArg) + " B"; }
            }


            namespace Colors {
                struct RGB_CONTAINER {
                public:
                    const int32_t HEX;
                    int32_t R{256};
                    int32_t G{256};
                    int32_t B{256};

                    explicit RGB_CONTAINER(int32_t hexValueArg = 0x000000)
                            : HEX(hexValueArg),
                              R((((hexValueArg >> 16) & 0xFF) / 255)),
                              G((((hexValueArg >> 8) & 0xFF) / 255)),
                              B((((hexValueArg) & 0xFF) / 255)) {}
                };
            }
        }
    }

    namespace IOManipulators {
        namespace FileManipulators {
            bool IsFileDescriptorValid(const int fileDescriptorArg) {
                return fcntl(fileDescriptorArg, F_GETFD) != -1 || errno != EBADF;
            }

            namespace Attributes {
#ifdef PLATFORM_WINDOWS

                bool SetFilePointerZ(void *fileHandleArg, uint64_t startAt = 0, uint64_t startFrom = FILE_BEGIN) {
                if (SetFilePointer(fileHandleArg, startAt, NULL, startFrom) == INVALID_SET_FILE_POINTER) {
                    return false;
                } else {
                    return true;
                }
            }

#endif
            }
            namespace Existence {
                inline bool CheckExistence0(const std::string &fileNameArg) {
                    std::ifstream f(fileNameArg.c_str());
                    return f.good();
                }

                inline bool CheckExistence1(const std::string &fileNameArg) {
                    if (FILE *file = std::fopen(fileNameArg.c_str(), "r")) {
                        fclose(file);
                        return true;
                    } else {
                        return false;
                    }
                }

                inline bool CheckExistence2(const std::string &fileNameArg) {
                    return (access(fileNameArg.c_str(), F_OK) != -1);
                }

                inline bool CheckExistence3(const std::string &fileNameArg) {
                    struct stat buffer{};
                    return (stat(fileNameArg.c_str(), &buffer) == 0);
                }

                inline bool CheckExistence4(const std::string &fileNameArg) {
                    return std::filesystem::exists(fileNameArg);
                }
            }

            namespace Paths {
                std::string MakeAbsolutPath(const std::string &filePathArg = __FILE__) {
                    return std::filesystem::absolute(filePathArg).string();
                }

                std::string MakePath(const std::string &fileNameArg) {

                    return std::filesystem::current_path().string() + PATH_DELIMITER + fileNameArg;
                }

                std::string GetCanonicalPath(const std::string &filePathArg = __FILE__) {
                    return std::filesystem::canonical(filePathArg).string();
                }

                std::string GetCurrentPath(void) {
                    return std::filesystem::current_path().string();
                }

                bool MoveAndRenameFile(const std::string &srcPathArg, const std::string &dstPathArg) {
                    try {
                        std::filesystem::rename(srcPathArg, dstPathArg);
                        return true;
                    } catch (std::filesystem::filesystem_error &filesystemError) {
                        return false;
                    }
                }

#ifdef PLATFORM_WINDOWS

                std::string GetCurrentFullPath(void) {
                char currentFullPath[MAX_PATH];
                GetModuleFileName(NULL, currentFullPath, MAX_PATH);
                return currentFullPath;
            }

#endif /* IOManipulators::FileManipulators::Paths -> GetCurrentFullPath - [PLATFORM_WINDOWS] */

            }
            namespace Operations {
                std::string ReadFromFile(const std::string &fileNameArg) {
                    if (IOManipulators::FileManipulators::Existence::CheckExistence4(fileNameArg)) {
                        std::ifstream file(fileNameArg, std::ios::in);
                        if (file.is_open()) {
                            std::string fileDataHolder;
                            file >> fileDataHolder;
                            file.close();
                            return fileDataHolder;
                        }
                    }
                    return "DOES_NOT_EXISTS";
                }

                bool
                WriteToFile(const std::string &fileNameArg, const std::string &dataArg = "", bool asAppendArg = false,
                            bool asBinaryArg = false) {
                    std::ofstream file(fileNameArg, std::ios::out);
                    if (asAppendArg) {
                        file << std::ios::app;
                    }
                    if (asBinaryArg) {
                        file << std::ios::binary;
                    }
                    if (file.is_open()) {
                        file << dataArg;
                        file.close();
                        return true;
                    } else {
                        return false;
                    }
                }

#ifdef PLATFORM_WINDOWS

                std::pair<uint64_t, BoosterException::InputOutput::InputOutputException>
            GetFileSizeX(void *fileHandleArg) {
                std::pair<uint64_t, BoosterException::InputOutput::InputOutputException> returnHolder(0,
                                                                                                      BoosterException::InputOutput::InputOutputException::Success);

                uint64_t fileSize = GetFileSize(fileHandleArg, NULL);
                if (fileSize == INVALID_FILE_SIZE) {
                    returnHolder.second = BoosterException::InputOutput::InputOutputException::FailedToGetFileSize;
                    return returnHolder;
                }

                returnHolder.first = fileSize;
                return returnHolder;
            }

            void *CreateFileRW(std::string fileNameArg) {
                if (fileNameArg.starts_with("\\\\") && fileNameArg.ends_with("\\")) {
                    fileNameArg.pop_back();
                }

                return CreateFile(fileNameArg.c_str(), (GENERIC_READ | GENERIC_WRITE),
                                  FILE_SHARE_WRITE | FILE_SHARE_READ,
                                  NULL,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            }

            void *CreateFileW(std::string fileNameArg) {
                if (fileNameArg.starts_with("\\\\") && fileNameArg.ends_with("\\")) {
                    fileNameArg.pop_back();
                }

                return CreateFile(fileNameArg.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE,
                                  NULL,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            }

            void *CreateFileR(std::string fileNameArg) {
                if (fileNameArg.starts_with("\\\\") && fileNameArg.ends_with("\\")) {
                    fileNameArg.pop_back();
                }

                return CreateFile(fileNameArg.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                  NULL,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            }

            namespace Read {
                std::pair<std::string, BoosterException::InputOutput::InputOutputException>
                ReadFileR(void *fileHandleArg, uint64_t bytesToReadArg) {
                    std::pair<std::string, BoosterException::InputOutput::InputOutputException> returnHolder("",
                                                                                                             BoosterException::InputOutput::InputOutputException::Success);

                    std::string dataBuffer;
                    dataBuffer.resize(bytesToReadArg);
                    DWORD retrievedBytes;
                    if (!ReadFile(fileHandleArg, dataBuffer.data(), bytesToReadArg, &retrievedBytes, NULL) ||
                        retrievedBytes != bytesToReadArg) {
                        returnHolder.second = BoosterException::InputOutput::InputOutputException::FailedToRead;
                        return returnHolder;
                    }

                    returnHolder.first = std::move(dataBuffer);
                    return returnHolder;
                }

                std::pair<std::string, BoosterException::InputOutput::InputOutputException>
                ReadFileAsHexR(void *fileHandleArg, uint64_t bytesToReadArg) {
                    std::pair<std::string, BoosterException::InputOutput::InputOutputException> returnHolder("",
                                                                                                             BoosterException::InputOutput::InputOutputException::Success);

                    std::pair<std::string, BoosterException::InputOutput::InputOutputException>
                            readFileReturnHolder = IOManipulators::FileManipulators::Operations::Read::ReadFileR(
                            fileHandleArg,
                            bytesToReadArg);
                    if (readFileReturnHolder.second != BoosterException::InputOutput::InputOutputException::Success) {
                        returnHolder.second = readFileReturnHolder.second;
                        return returnHolder;
                    }
                    returnHolder.first = readFileReturnHolder.first;
                    returnHolder.first = StringManipulators::Convertors::TextToHex::StringToHex2(returnHolder.first);

                    return returnHolder;
                }
            }

            namespace Write {
                BoosterException::InputOutput::InputOutputException
                WriteFileW(void *fileHandleArg, const std::string &dataBuffer) {
                    DWORD bytesWritten;
                    if (!WriteFile(fileHandleArg, dataBuffer.data(), dataBuffer.size() * sizeof(char), &bytesWritten,
                                   NULL) ||
                        bytesWritten != dataBuffer.size()) {
                        return BoosterException::InputOutput::InputOutputException::FailedToWrite;
                    }
                    return BoosterException::InputOutput::InputOutputException::Success;
                }


                BoosterException::InputOutput::InputOutputException
                WriteAsHexW(void *fileHandleArg, const std::string &dataBuffer) {
                    BoosterException::InputOutput::InputOutputException
                            returnHolder(BoosterException::InputOutput::InputOutputException::Success);

                    BoosterException::InputOutput::InputOutputException
                            readFileReturnHolder = IOManipulators::FileManipulators::Operations::Write::WriteFileW(
                            fileHandleArg, StringManipulators::Convertors::HexToText::HexToString1(dataBuffer));
                    if (readFileReturnHolder != BoosterException::InputOutput::InputOutputException::Success) {
                        returnHolder = readFileReturnHolder;
                        return returnHolder;
                    }

                    return returnHolder;
                }
            }
#endif /* System -> CreateFileRW : GetDiskGeometry : GetDeviceBytesPerSector - [PLATFORM_WINDOWS]  */
            }

            void CloseFileDescriptor(const int fileDescriptorArg) {
                if (FileManipulators::IsFileDescriptorValid(fileDescriptorArg)) {
                    close(fileDescriptorArg);
                }
            }
        }
    }

    namespace JsonManipulators {
        rapidjson::Document JsonParse(std::string rawJsonStringArg) {
            rapidjson::Document jsonDocTemp;
            jsonDocTemp.Parse(rawJsonStringArg.c_str());
            return jsonDocTemp;
        }

        rapidjson::StringBuffer JsonDocumentToJsonStringBuffer(rapidjson::Document &jsonDocumentArg) {
            rapidjson::StringBuffer stringBuffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(stringBuffer);
            jsonDocumentArg.Accept(writer);
            return stringBuffer;
        }

        bool IsValidJson(const rapidjson::Document &jsonDocumentArg) {
            return (!jsonDocumentArg.HasParseError()
                    &&
                    rapidjson::SchemaValidator(rapidjson::SchemaDocument(jsonDocumentArg)).IsValid());
        }

        bool IsValidJson(std::string &rawJsonStringArg) {
            return IsValidJson(rapidjson::Document(JsonParse(rawJsonStringArg)));
        }
    }

#ifdef PLATFORM_WINDOWS
    namespace RegistryManipulators {
    namespace Paths {
        namespace Startup {
            const std::string StartupAlways{R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Run)"};
            const std::string StartupOnce{R"(SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce)"};
        }
    }
    namespace _internal {
        const std::string defaultRegistryItemContainerPathArg{"Control Panel\\Keyboard\\_internal"};
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

        std::string registryEntrySetter(const registryEntries &registryEntry = registryEntries::HKEY_CURRENT_USER_) {
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
        registryPropertyTypeSetter(const registryPropertyTypes &registryPropertyType = registryPropertyTypes::String) {
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


        inline bool CheckForError(const std::string &commandOutputArg) {
            return commandOutputArg.contains(ERROR_PREFIX);
        }

        inline bool CheckForSuccess(const std::string &commandOutputArg) {
            return commandOutputArg.contains(SUCCESS_PREFIX);
        }
    }

    namespace WinAPI {
        bool SetOrEditItemPropertyValue(const std::string &registryItemPropertyNewValueArg,
                                        const std::string &registryItemPropertyNameArg,
                                        const std::string &registryItemContainerPathArg = _internal::defaultRegistryItemContainerPathArg,
                                        HKEY hKeyArg = HKEY_CURRENT_USER) {
            HKEY hKey;
            LONG lnRes = RegOpenKeyEx(hKeyArg,
                                      registryItemContainerPathArg.c_str(),
                                      0, KEY_WRITE,
                                      &hKey);
            if (ERROR_SUCCESS == lnRes) {
                lnRes = RegSetValueEx(hKey,
                                      registryItemPropertyNameArg.c_str(),
                                      0,
                                      REG_SZ,
                                      (unsigned char *) registryItemPropertyNewValueArg.c_str(),
                                      registryItemPropertyNewValueArg.size());
                RegCloseKey(hKey);
                return true;
            }

            RegCloseKey(hKey);
            return false;

        }

        bool AddProgramToStartup(const std::string &programPathArg, const std::string &programNameArg = "001",
                                 HKEY hKeyArg = HKEY_CURRENT_USER) {
            return RegistryManipulators::WinAPI::SetOrEditItemPropertyValue(programPathArg, programNameArg,
                                                                            RegistryManipulators::Paths::Startup::StartupAlways,
                                                                            hKeyArg);
        }
    }


    // ---------------------------- [ContainerManipulators] ----------------------------


    template<_internal::registryEntries registryEntry = _internal::registryEntries::HKEY_CURRENT_USER_>
    bool
    checkForItemContainerExistence(
            const std::string &registryItemContainerPathArg = _internal::defaultRegistryItemContainerPathArg) {
        const std::string &fullPath{registryEntrySetter(registryEntry) + registryItemContainerPathArg};


        const std::string commandTemp{
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
    GetItemContainer(
            const std::string &registryItemContainerPathArg = _internal::defaultRegistryItemContainerPathArg) {
        if (checkForItemContainerExistence(registryItemContainerPathArg)) {
            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPathArg};

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
    std::string NewItemContainer(const std::string &registryItemContainerNameArg,
                                 const std::string &registryItemContainerPathArg = "Control Panel\\Keyboard") {

        if (!checkForItemContainerExistence(
                registryItemContainerPathArg + '\\' + registryItemContainerNameArg)) {
            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPathArg};

            std::string commandTemp{
                    _internal::powershellExecutionCommand + " \"New-Item -Path '" + fullPath +
                    "' -Name '" + registryItemContainerNameArg +
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
            const std::string &registryItemContainerPathArg = _internal::defaultRegistryItemContainerPathArg) {

        if (checkForItemContainerExistence(registryItemContainerPathArg)) {
            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPathArg};

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
            const std::string &registryItemContainerPathArg = _internal::defaultRegistryItemContainerPathArg) {

        if (checkForItemContainerExistence(registryItemContainerPathArg)) {
            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPathArg};

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
    checkForItemPropertyValueExistence(const std::string &registryItemPropertyNameArg,
                                       const std::string &registryItemContainerPathArg = _internal::defaultRegistryItemContainerPathArg) {
        const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPathArg};

        std::string commandTemp{
                _internal::powershellExecutionCommand + " \"Get-ItemPropertyValue -Path '" + fullPath +
                "' -Name '" +
                registryItemPropertyNameArg +
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
    GetItemPropertyValue(const std::string &registryItemPropertyNameArg,
                         const std::string &registryItemContainerPathArg = _internal::defaultRegistryItemContainerPathArg) {
        std::string propertyValueState = checkForItemPropertyValueExistence(registryItemPropertyNameArg,
                                                                            registryItemContainerPathArg);
        if (propertyValueState == "DOES_EXISTS") {
            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPathArg};

            std::string commandTemp{
                    _internal::powershellExecutionCommand + " \"Get-ItemPropertyValue -Path '" + fullPath +
                    "' -Name '" +
                    registryItemPropertyNameArg +
                    "' " + _internal::powershellEOFCommand};

            std::string commandResult = System::ExecuteCommand(commandTemp);

            if (_internal::CheckForError(commandResult)) {
                return _internal::ERROR_RETURN;
            } else {
                StringManipulators::Trim::trim(commandResult);
                return commandResult;
            }
        } else {
            return propertyValueState;
        }
    }

    template<_internal::registryEntries registryEntry = _internal::registryEntries::HKEY_CURRENT_USER_>
    std::string
    SetOrEditItemPropertyValue(const std::string &registryItemPropertyNewValueArg,
                               const std::string &registryItemPropertyNameArg,
                               const std::string &registryItemContainerPathArg = _internal::defaultRegistryItemContainerPathArg) {
        if (checkForItemContainerExistence(registryItemContainerPathArg)) {

            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPathArg};

            std::string commandTemp{
                    _internal::powershellExecutionCommand + " \"Set-ItemProperty -Path '" + fullPath +
                    "' -Name '" + registryItemPropertyNameArg +
                    "' -Value '" + registryItemPropertyNewValueArg +
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
    NewItemPropertyValue(const std::string &registryItemPropertyValueArg,
                         const std::string &registryItemPropertyNameArg,
                         const std::string &registryItemContainerPathArg = _internal::defaultRegistryItemContainerPathArg) {
        std::string itemPropertyState = checkForItemPropertyValueExistence(registryItemPropertyNameArg,
                                                                           registryItemContainerPathArg);

        if (checkForItemContainerExistence(registryItemContainerPathArg)) {
            if (itemPropertyState != "DOES_EXISTS") {

                const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPathArg};
                const std::string propertyType{registryPropertyTypeSetter(registryPropertyType)};

                std::string commandTemp{
                        _internal::powershellExecutionCommand + " \"New-ItemProperty -Path '" + fullPath +
                        "' -Name '" + registryItemPropertyNameArg +
                        "' -Value '" + registryItemPropertyValueArg +
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
    std::string RemoveItemPropertyValue(const std::string &registryItemPropertyNameArg,
                                        const std::string &registryItemContainerPathArg = _internal::defaultRegistryItemContainerPathArg) {
        std::string itemPropertyState = checkForItemPropertyValueExistence(registryItemPropertyNameArg,
                                                                           registryItemContainerPathArg);
        if (itemPropertyState == "DOES_EXISTS") {
            const std::string fullPath{registryEntrySetter(registryEntry) + registryItemContainerPathArg};

            std::string commandTemp{
                    _internal::powershellExecutionCommand + " \"Remove-ItemProperty -Path '" + fullPath +
                    "' -Name '" +
                    registryItemPropertyNameArg + "'\""};

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
}


#endif //BOOSTER_HPP
