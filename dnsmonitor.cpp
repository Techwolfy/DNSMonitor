//
// Includes
//

#define UNICODE
#include <windows.h>
#include <stdio.h>
#include <evntrace.h>
#include <tdh.h>

//
// Libraries
//

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

//
// Constants
//

#define DNS_LOGGER_NAME L"DNSMonitor"
#define DNS_PROVIDER_NAME L"Microsoft-Windows-DNS-Client"
#define DNS_QUERY_EVENT_ID 3006
#define DNS_CACHED_RESOLUTION_EVENT_ID 3018
#define DNS_HOT_RESOLUTION_EVENT_ID 3020

// Microsoft-Windows-DNS-Client {1c95126e-7eea-49a9-a3fe-a378b03ddb4d}
static const GUID DnsClientProviderGuid = {0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};

//
// Globals
//

volatile BOOL g_fQuit = FALSE;
TRACEHANDLE g_hProcessTrace = INVALID_PROCESSTRACE_HANDLE;

//
// Callbacks
//

BOOL WINAPI SignalHandler(
    DWORD dwSignal
)
{
    if (dwSignal == CTRL_C_EVENT ||
        dwSignal == CTRL_CLOSE_EVENT)
    {
        g_fQuit = TRUE;

        CloseTrace(g_hProcessTrace);
        g_hProcessTrace = INVALID_PROCESSTRACE_HANDLE;

        return TRUE;
    }

    return FALSE;
}

ULONG WINAPI BufferCallback(
    PEVENT_TRACE_LOGFILE pEventTraceLogfile
)
{
    return !g_fQuit;
}

VOID WINAPI EventRecordCallback(
    PEVENT_RECORD pEventRecord
)
{
    DWORD dwError = ERROR_SUCCESS;
    PTRACE_EVENT_INFO pTraceEventInfo = NULL;
    DWORD dwTraceEventInfoSize = 0;
    SYSTEMTIME st = {};
    SYSTEMTIME stLocal = {};
    PEVENT_PROPERTY_INFO pEventPropertyInfo = NULL;
    PWSTR pszPropertyName = NULL;
    PROPERTY_DATA_DESCRIPTOR PropertyDataDesc;
    PBYTE pPropertyData = NULL;
    DWORD dwPropertySize = 0;

    //
    // Decode the event
    //

    dwError = TdhGetEventInformation(pEventRecord, 0, NULL, NULL, &dwTraceEventInfoSize);
    if (dwError != ERROR_INSUFFICIENT_BUFFER)
    {
        wprintf(L"Failed to get event information: %#x\n", dwError);
        return;
    }

    pTraceEventInfo = (PTRACE_EVENT_INFO)malloc(dwTraceEventInfoSize);
    if (pTraceEventInfo == NULL)
    {
        wprintf(L"Failed to allocate memory for event info: %#x\n", ERROR_OUTOFMEMORY);
        return;
    }

    dwError = TdhGetEventInformation(pEventRecord, 0, NULL, pTraceEventInfo, &dwTraceEventInfoSize);
    if (dwError != ERROR_SUCCESS)
    {
        wprintf(L"Failed to get event information: %#x\n", dwError);
        return;
    }

    //
    // Filter out unnecessary events
    //

    if (pTraceEventInfo->EventDescriptor.Id != DNS_CACHED_RESOLUTION_EVENT_ID &&
        pTraceEventInfo->EventDescriptor.Id != DNS_HOT_RESOLUTION_EVENT_ID)
    {
        return;
    }

    //
    // Print the event timestamp
    //

    FileTimeToSystemTime((FILETIME *)&pEventRecord->EventHeader.TimeStamp, &st);
    SystemTimeToTzSpecificLocalTime(NULL, &st, &stLocal);

    wprintf(L"%02d/%02d/%02d %02d:%02d:%02d.%03d: ",
            stLocal.wMonth,
            stLocal.wDay,
            stLocal.wYear,
            stLocal.wHour,
            stLocal.wMinute,
            stLocal.wSecond,
            stLocal.wMilliseconds);

    //
    // Print the event type
    //

    if (pTraceEventInfo->EventDescriptor.Id == DNS_CACHED_RESOLUTION_EVENT_ID)
    {
        wprintf(L"[Cache  ] ");
    }
    else
    {
        wprintf(L"[Network] ");
    }

    //
    // Print the event details
    //

    for (DWORD i = 0; i < pTraceEventInfo->TopLevelPropertyCount; i++)
    {
        pEventPropertyInfo = &pTraceEventInfo->EventPropertyInfoArray[i];
        pszPropertyName = (PWSTR)((PBYTE)pTraceEventInfo + pEventPropertyInfo->NameOffset);

#if DBG
        wprintf(L"\tPropertyName: %ws, Length: %d, InType: %u, Data: ",
                pszPropertyName,
                pEventPropertyInfo->length,
                pEventPropertyInfo->nonStructType.InType);
#else
        if (wcscmp(pszPropertyName, L"QueryName") != 0)
        {
            //
            // Only show queried domain names
            //

            continue;
        }
#endif
       
        PropertyDataDesc.PropertyName = (ULONGLONG)pszPropertyName;
        PropertyDataDesc.ArrayIndex = ULONG_MAX;

        dwError = TdhGetPropertySize(pEventRecord,
                                     0,
                                     NULL,
                                     1,
                                     &PropertyDataDesc,
                                     &dwPropertySize);
        if (dwError != ERROR_SUCCESS)
        {
            wprintf(L"\nFailed to get event property size: %#x\n", dwError);
            continue;
        }

        pPropertyData = (PBYTE)malloc(dwPropertySize);
        if (pPropertyData == NULL)
        {
            wprintf(L"\nFailed to allocate memory for property buffer: %#x\n", ERROR_OUTOFMEMORY);
            continue;
        }
       
        dwError = TdhGetProperty(pEventRecord,
                                 0,
                                 NULL,
                                 1,
                                 &PropertyDataDesc,
                                 dwPropertySize,
                                 pPropertyData);
        if (dwError != ERROR_SUCCESS)
        {
            wprintf(L"\nFailed to get event property: %#x\n", dwError);
            continue;
        }

        if (pEventPropertyInfo->nonStructType.InType == TDH_INTYPE_UNICODESTRING)
        {
            wprintf(L"%ws\n", (PWSTR)pPropertyData);
        }
        else if (pEventPropertyInfo->nonStructType.InType == TDH_INTYPE_UINT32)
        {
            wprintf(L"%d\n", *(PULONG)pPropertyData);
        }
        else if (pEventPropertyInfo->nonStructType.InType == TDH_INTYPE_UINT64)
        {
            wprintf(L"%lld\n", *(PULONGLONG)pPropertyData);
        }
    }
}

int main(int argc, char *argv[])
{
    DWORD dwError = ERROR_SUCCESS;
    TRACEHANDLE hTrace = NULL;
    BYTE pBuffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 + 1024] = {};
    PEVENT_TRACE_PROPERTIES pEventTraceProperties = (PEVENT_TRACE_PROPERTIES)&pBuffer;
    EVENT_TRACE_LOGFILE EventTraceLogfile = {};

    //
    // Set signal handler to clean up trace session on exit
    //

    if (!SetConsoleCtrlHandler(SignalHandler, TRUE))
    {
        wprintf(L"Failed to set signal handler: %#x\n", GetLastError());
        goto Exit;
    }

    //
    // Start trace session
    //

    pEventTraceProperties->Wnode.BufferSize = sizeof(pBuffer);
    pEventTraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pEventTraceProperties->BufferSize = 1024;
    pEventTraceProperties->MinimumBuffers = 2;
    pEventTraceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pEventTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    dwError = StartTrace(&hTrace, DNS_LOGGER_NAME, pEventTraceProperties);
    if (dwError != ERROR_SUCCESS)
    {
        wprintf(L"Failed to start trace session: %#x\n", dwError);
        goto Exit;
    }

    //
    // Add DNS provider to trace session
    //

    dwError = EnableTraceEx2(hTrace,
                             &DnsClientProviderGuid,
                             EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                             TRACE_LEVEL_INFORMATION,
                             0,
                             0,
                             0,
                             NULL);
    if (dwError != ERROR_SUCCESS)
    {
        wprintf(L"Failed to add DNS provider to trace session: %#x\n", dwError);
        goto Exit;
    }

    //
    // Connect to trace session
    //

    EventTraceLogfile.LoggerName = DNS_LOGGER_NAME;
    EventTraceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    EventTraceLogfile.BufferCallback = BufferCallback;
    EventTraceLogfile.EventRecordCallback = EventRecordCallback;

    g_hProcessTrace = OpenTrace(&EventTraceLogfile);
    if (g_hProcessTrace == INVALID_PROCESSTRACE_HANDLE)
    {
        dwError = GetLastError();
        wprintf(L"Failed to open trace session: %#x\n", dwError);
        goto Exit;
    }

    //
    // Start consuming events
    //

    dwError = ProcessTrace(&g_hProcessTrace, 1, NULL, NULL);
    if (dwError != ERROR_SUCCESS)
    {
        wprintf(L"Failed to process trace events: %#x\n", dwError);
        goto Exit;
    }

Exit:

    //
    // Always attempt to clean up the trace session
    //

    ZeroMemory(pEventTraceProperties, sizeof(pBuffer));
    pEventTraceProperties->Wnode.BufferSize = sizeof(pBuffer);
    dwError = StopTrace(NULL, DNS_LOGGER_NAME, pEventTraceProperties);
    if (dwError != ERROR_SUCCESS)
    {
        wprintf(L"Failed to stop trace session: %#x\n", dwError);
    }

    if (g_hProcessTrace != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(g_hProcessTrace);
        g_hProcessTrace = INVALID_PROCESSTRACE_HANDLE;
    }

    if (hTrace != NULL)
    {
        CloseTrace(hTrace);
        hTrace = NULL;
    }

    return dwError;
}
