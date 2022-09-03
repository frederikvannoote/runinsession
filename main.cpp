#include <windows.h>
#include <processthreadsapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <tchar.h>
#include <UserEnv.h>
#include <iostream>
#include <filesystem>

const int MAXSIZE = 16384; // size does matter


std::string getLastErrorAsString()
{
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0)
    {
        return std::string(); // No error message has been recorded
    }

    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);

    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}

DWORD WINAPI GetInteractiveConsoleSessionID()
{
    HMODULE hkernDll = GetModuleHandleW(_T("kernel32.dll"));
    if (hkernDll)
    {
        DWORD (WINAPI* pWTSGetActiveConsoleSessionId)() =
            (DWORD (WINAPI*)()) GetProcAddress(hkernDll, "WTSGetActiveConsoleSessionId");

        if (pWTSGetActiveConsoleSessionId)
        {
            return pWTSGetActiveConsoleSessionId();
        }
    }

    return 0; // Win2k and below default is session 0 since there is no fast user switching
}

BOOL IsLocalSid( PSID ps )
{
    static PSID pComparisonSid = NULL;

    if ( pComparisonSid == NULL )
    {
        // build "BUILTIN\LOCAL" SID for comparison: S-1-2-0
        SID_IDENTIFIER_AUTHORITY sia = SECURITY_LOCAL_SID_AUTHORITY;
        AllocateAndInitializeSid( &sia, 1, 0, 0, 0, 0, 0, 0, 0, 0, &pComparisonSid );
    }

    return EqualSid( ps, pComparisonSid );
}

BOOL IsInteractiveSid( PSID ps )
{
    static PSID pComparisonSid = NULL;

    if ( pComparisonSid == NULL )
    {
        // build "BUILTIN\LOCAL" SID for comparison: S-1-5-4
        SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY; // "-5-"
        AllocateAndInitializeSid( &sia, 1, 4, 0, 0, 0, 0, 0, 0, 0, &pComparisonSid );
    }

    return EqualSid( ps, pComparisonSid );
}

BOOL IsConsoleLogonSid( PSID ps )
{
    static PSID pComparisonSid = NULL;

    if ( pComparisonSid == NULL )
    {
        // build "BUILTIN\LOCAL" SID for comparison: S-1-2-1
        SID_IDENTIFIER_AUTHORITY sia = SECURITY_LOCAL_SID_AUTHORITY; // "-2-"
        AllocateAndInitializeSid( &sia, 1, 1, 0, 0, 0, 0, 0, 0, 0, &pComparisonSid );
    }

    return EqualSid( ps, pComparisonSid );
}

BOOL CheckToken(HANDLE hp)
{
    HANDLE ht = NULL;
    DWORD needed;
    DWORD i;

    TOKEN_GROUPS *ptg = NULL ;

    // these three keep track of what we found in the token
    bool haveLocalSid = false, haveLogonSid = false, haveInteractiveSid = false;

    if ( ! OpenProcessToken( hp, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &ht ) )
    {
        std::cout << "OpenProcessToken() returned error " << getLastErrorAsString() << std::endl;
    }
    else
    {

        {
            // token groups
            ptg = (TOKEN_GROUPS *) malloc( MAXSIZE );
            if ( ! GetTokenInformation( ht, TokenGroups, ptg, MAXSIZE, &needed ) )
            {
                std::cout << "GetTokenInformation() returned error " << getLastErrorAsString() << std::endl;
            }
            else
            {
                for ( i = 0; i < ptg->GroupCount; ++ i )
                {
                    if ( IsLocalSid( ptg->Groups[i].Sid ) )
                    {
                        haveLocalSid = true;
                    }
                    if ( IsInteractiveSid( ptg->Groups[i].Sid ) )
                    {
                        haveInteractiveSid = true;
                    }
                    if ( IsConsoleLogonSid( ptg->Groups[i].Sid ) )
                    {
                        haveLogonSid = true;
                    }
                }
            }
        }
    }

    if (ptg != NULL)
    {
        free( ptg );
    }

    return haveLocalSid && haveInteractiveSid && haveLogonSid;
}

/**
 * @brief RunInUserSession
 * @param Path
 * @param WorkingDir
 * @param Args
 * @param ShowWindowFlags
 * @param pi
 * @param Priority
 * @param asLogonUser if false, run as system account. if true a user must be logged on to start the process
 * @return
 * @note If a process was already started with the same path before, it will be terminated first
 */
BOOL RunInUserSession(std::wstring Path, std::wstring WorkingDir, DWORD activeSessionId, BOOL asLogonUser)
{
    PROCESS_INFORMATION procInfo;
    ZeroMemory(&procInfo, sizeof(procInfo));
    STARTUPINFOW si;
    DWORD	processId = 0;
    DWORD	dwCreationFlags;

    if (activeSessionId == 0)
    {
        activeSessionId = GetInteractiveConsoleSessionID();
    }

    HANDLE job = CreateJobObject(NULL, NULL);

    JOBOBJECT_BASIC_LIMIT_INFORMATION info;
    info.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION extendedInfo;
    extendedInfo.BasicLimitInformation = info;

    DWORD length = sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
    LPVOID extendedInfoPtr = static_cast<void*>(&extendedInfo);

    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, extendedInfoPtr, length))
        std::cerr << "Unable to set Job Object information, error : " << getLastErrorAsString() << std::endl;

    //////////////////////////////////////////
    // Find the winlogon process
    ////////////////////////////////////////

    PROCESSENTRY32W procEntry;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        std::cerr << "CreateToolhelp32Snapshot() returned and invalid handle" << std::endl;
        return FALSE;
    }

    // if asLogonUser, search for a process that runs as logon user
    // else search for the winlogon process

    procEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnap, &procEntry))
    {
        std::cerr << "Process32First() returned error " << getLastErrorAsString() << std::endl;
        CloseHandle(hSnap);
        return FALSE;
    }

    BOOL processFound = FALSE ;
    DWORD processSessionId;
    do
    {
        if (asLogonUser)
        {
            if (_wcsicmp(procEntry.szExeFile, L"dwm.exe") != 0)
            {
                processId = procEntry.th32ProcessID;

                HANDLE hp = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ| PROCESS_DUP_HANDLE, FALSE, processId );
                if (hp == NULL || (hp == INVALID_HANDLE_VALUE))
                {
                    std::cerr << "OpenProcess(" << processId << ") returned error " << getLastErrorAsString() << std::endl;
                }
                else
                {
                    if (ProcessIdToSessionId(processId, &processSessionId) && processSessionId == activeSessionId)
                    {
                        if (CheckToken(hp))
                        {
                            std::cout << "Matching process found: " << procEntry.szExeFile << std::endl;
                            processFound = TRUE;
                            break;
                        }
                    }
                    CloseHandle( hp );
                }
            }
        }
        else if (_wcsicmp(procEntry.szExeFile, L"winlogon.exe") == 0)
        {
            // We found a winlogon process...make sure it's running in the console session
            processSessionId = 0;
            if (ProcessIdToSessionId(procEntry.th32ProcessID, &processSessionId) && processSessionId == activeSessionId)
            {
                processId = procEntry.th32ProcessID;
                processFound = TRUE;
                break;
            }
        }

    }
    while (Process32NextW(hSnap, &procEntry));

    CloseHandle(hSnap);

    if (!processFound)
    {
        if (asLogonUser)
        {
            std::cout << "No logon and interactive Pid found" ;
        }
        else
        {
            std::cout << "Winlogon Pid not found" ;
        }
        return FALSE ;
    }

    ////////////////////////////////////////////////////////////////////////

    //WTSQueryUserToken(dwSessionId,&hUserToken);
    dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW; // | CREATE_NEW_CONSOLE;
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    si.cb = sizeof(STARTUPINFOW);
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    TOKEN_PRIVILEGES tp;
    LUID luid;

    HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, processId);
    if (hProcess == NULL)
    {
        std::cerr << "OpenProcess(" << processId << ") returned error " << getLastErrorAsString() << std::endl;
        return FALSE ;
    }

    HANDLE hPToken;
    if(!::OpenProcessToken(hProcess,
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY |
        TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
        TOKEN_ADJUST_SESSIONID | TOKEN_READ | TOKEN_WRITE,
        &hPToken))
    {
        std::cerr << processId << " " << hProcess << " " << hPToken << " " << "OpenProcessToken() failed with error: " << getLastErrorAsString() << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        std::cerr << "Lookup Privilege value Error: " << getLastErrorAsString() << std::endl;
        CloseHandle(hProcess);
        CloseHandle(hPToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid =luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    HANDLE hUserTokenDup;
    if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hUserTokenDup))
    {
        std::cerr << "DuplicateTokenEx() Error: " << getLastErrorAsString() << std::endl;
        CloseHandle(hProcess);
        CloseHandle(hPToken);
        return FALSE;
    }

    //Adjust Token privilege
    if (!SetTokenInformation(hUserTokenDup, TokenSessionId, &activeSessionId, sizeof(DWORD)))
    {
        std::cerr <<  "SetTokenInformation Error: " <<  getLastErrorAsString() << std::endl;
        CloseHandle(hProcess);
        CloseHandle(hUserTokenDup);
        CloseHandle(hPToken);
        return FALSE;
    }

    if (!AdjustTokenPrivileges(hUserTokenDup, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, NULL))
    {
        std::cerr << "AdjustTokenPrivileges Error: " << getLastErrorAsString() << std::endl;
        CloseHandle(hProcess);
        CloseHandle(hUserTokenDup);
        CloseHandle(hPToken);
        return FALSE;
    }

    LPVOID pEnv = NULL;
    if (CreateEnvironmentBlock(&pEnv, hUserTokenDup, TRUE))
    {
        dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
    }
    else
    {
        pEnv=NULL;
    }

    // Launch the process in the client's logon session.
    std::wcout << "Starting process " << Path << " in " << WorkingDir << std::endl;
    BOOL bResult = CreateProcessAsUserW(
        hUserTokenDup,		// client's access token
        NULL,				// file to execute
        Path.data(),
        NULL,				// pointer to process SECURITY_ATTRIBUTES
        NULL,				// pointer to thread SECURITY_ATTRIBUTES
        FALSE,				// handles are not inheritable
        dwCreationFlags,	// creation flags
        pEnv,				// pointer to new environment block
        ((WorkingDir.empty())? NULL : (LPWSTR)WorkingDir.data()),
        &si,				// pointer to STARTUPINFO structure
        &procInfo);			// receives information about new process

    if (!bResult)
    {
        std::cerr << bResult << " CreateProcessAsUser failed to start program. error code = " << getLastErrorAsString();
    }
    else
    {
        std::cout << "Application started with PID " << procInfo.dwProcessId << " in session with ID " << activeSessionId << std::endl;
        CloseHandle(procInfo.hThread);
    }

    if (!AssignProcessToJobObject(job, procInfo.hProcess))
    {
        std::cerr << "Could not assign job object." << std::endl;
        return 1;
    }

    if (!WaitForSingleObject(procInfo.hProcess, INFINITE))
    {
        std::cerr << "Could not wait on process: " << getLastErrorAsString() << std::endl;
        return 1;
    }

    CloseHandle(hProcess);
    CloseHandle(hUserTokenDup);
    CloseHandle(hPToken);

    return bResult;
}

int main(int, char *argv[])
{
    std::filesystem::path cwd = std::filesystem::current_path();
    const std::wstring workingdir = cwd.wstring();

    const std::string str(argv[1]);
    const std::wstring commandline(str.begin(), str.end());

    // Now start the core service in the given (active) user session.
    DWORD session = 0;
    if (!RunInUserSession(commandline, workingdir, session, false))
    {
        std::wcerr << "Could not start " << commandline << " in session " << session << std::endl;
    }

    return 0;
}
