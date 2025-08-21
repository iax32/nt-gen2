#include "nt.hpp"
#include "nt_def.hpp"

// nt.cpp

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>   // NtQuerySystemInformation, structs
#include <ntstatus.h>   // STATUS_INFO_LENGTH_MISMATCH, etc.


#include <vector>
#include <stdexcept>
#include <Windows.h>
#include <winternl.h>

/*

handles buffer size races correctly (STATUS_INFO_LENGTH_MISMATCH loop).

checks for nulls and edge cases so it won’t crash as easily.

processes the final list entry so results are complete.

does case-insensitive comparisons for correctness.

*/

std::size_t nt::find_process_id(std::wstring_view process_name)
{
    ULONG size = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &size);

    if (status != STATUS_INFO_LENGTH_MISMATCH || size == 0)
        throw std::runtime_error("failed to query SystemProcessInformation size"); // tighten error path

    std::vector<std::uint8_t> buffer(size);

    for (;;)
    {
        status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(),
            static_cast<ULONG>(buffer.size()), &size);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            buffer.resize(size ? size : buffer.size() * 2);
            continue;
        }
        if (!NT_SUCCESS(status))
            throw std::runtime_error("NtQuerySystemInformation(SystemProcessInformation) failed");
        break;
    }

    auto* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buffer.data());
    std::size_t pid = 0;

    for (;;)
    {
        if (spi->ImageName.Buffer && spi->ImageName.Length)
        {
            std::wstring_view name(spi->ImageName.Buffer, spi->ImageName.Length / sizeof(wchar_t));
            // case-insensitive substring match (Windows is case-insensitive for file names)
            auto tolower = [](wchar_t c) { return static_cast<wchar_t>(::towlower(c)); };
            auto contains_icase = [&](std::wstring_view hay, std::wstring_view needle)
                {
                    if (needle.empty()) return true;
                    for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
                    {
                        bool eq = true;
                        for (size_t j = 0; j < needle.size(); ++j)
                            if (tolower(hay[i + j]) != tolower(needle[j])) { eq = false; break; }
                        if (eq) return true;
                    }
                    return false;
                };

            if (contains_icase(name, process_name))
            {
                pid = reinterpret_cast<std::size_t>(spi->UniqueProcessId);
                break;
            }
        }

        if (spi->NextEntryOffset == 0) break; // IMPORTANT: check the last entry too
        spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
            reinterpret_cast<std::uint8_t*>(spi) + spi->NextEntryOffset);
    }

    return pid;
}


std::uint8_t* nt::find_kernel_module(std::string_view module_name)
{
    ULONG size = 0;
    NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(0x0B), nullptr, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH || size == 0)
        throw std::runtime_error("failed to query SystemModuleInformation size");

    std::vector<std::uint8_t> buffer(size);

    for (;;)
    {
        status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(0x0B),
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &size);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            buffer.resize(size ? size : buffer.size() * 2);
            continue;
        }
        if (!NT_SUCCESS(status))
            throw std::runtime_error("NtQuerySystemInformation(SystemModuleInformation) failed");
        break;
    }

    auto* process_modules = reinterpret_cast<nt_def::s_process_modules*>(buffer.data());
    if (!process_modules) return nullptr;

    std::uint8_t* image_base = nullptr;

    
    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(process_modules->numer_of_modules); ++i)
    {
        auto& m = process_modules->modules[i];
        const char* name = reinterpret_cast<const char*>(m.full_path_name + m.offset);
        if (!name) continue;

        // case-insensitive match 
        std::string_view sv(name);
        auto tolower = [](char c) { return static_cast<char>(::tolower(static_cast<unsigned char>(c))); };
        auto ends_with_icase = [&](std::string_view hay, std::string_view needle)
            {
                if (needle.size() > hay.size()) return false;
                size_t off = hay.size() - needle.size();
                for (size_t j = 0; j < needle.size(); ++j)
                    if (tolower(hay[off + j]) != tolower(needle[j])) return false;
                return true;
            };

        if (sv.find(module_name) != std::string::npos || ends_with_icase(sv, module_name))
        {
            image_base = reinterpret_cast<std::uint8_t*>(m.image_base);
            break;
        }
    }

    return image_base;
}


std::uint8_t* nt::find_module(std::wstring_view module_name)
{
#ifdef _M_X64
    PEB* peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
    PEB* peb = reinterpret_cast<PEB*>(__readfsdword(0x30));
#endif
    if (!peb) throw std::runtime_error("failed to find process environment block");

    PEB_LDR_DATA* ldr = peb->Ldr;
    if (!ldr) throw std::runtime_error("failed to get ldr data");

    std::uint8_t* image_base = nullptr;

    for (LIST_ENTRY* e = ldr->InMemoryOrderModuleList.Flink;
        e != &ldr->InMemoryOrderModuleList;
        e = e->Flink)
    {
        auto* ldr_entry = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (ldr_entry->FullDllName.Buffer && ldr_entry->FullDllName.Length)
        {
            std::wstring_view dll(ldr_entry->FullDllName.Buffer, ldr_entry->FullDllName.Length / sizeof(wchar_t));
            // case-insensitive substring match
            auto tolower = [](wchar_t c) { return static_cast<wchar_t>(::towlower(c)); };
            auto contains_icase = [&](std::wstring_view hay, std::wstring_view needle)
                {
                    if (needle.empty()) return true;
                    for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
                    {
                        bool eq = true;
                        for (size_t j = 0; j < needle.size(); ++j)
                            if (tolower(hay[i + j]) != tolower(needle[j])) { eq = false; break; }
                        if (eq) return true;
                    }
                    return false;
                };

            if (contains_icase(dll, module_name))
            {
                image_base = static_cast<std::uint8_t*>(ldr_entry->DllBase);
                break;
            }
        }
    }

    return image_base;
}

PPEB GetPEB() {
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

void* GetModuleBaseAddress(const char* moduleName) {
    PPEB peb = GetPEB();
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY list = &ldr->InMemoryOrderModuleList;
    
    for (PLIST_ENTRY entry = list->Flink; entry != list; entry = entry->Flink) {
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        
        if (module->BaseDllName.Buffer) {
            if (_wcsicmp(module->BaseDllName.Buffer, std::wstring(moduleName, moduleName + strlen(moduleName)).c_str()) == 0) {
                return module->DllBase;
            }
        }
    }
    
    return nullptr;
}


