; // This is the header section.


SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )


FacilityNames=(System=0x0:FACILITY_SYSTEM
               Runtime=0x2:FACILITY_RUNTIME
               Stubs=0x3:FACILITY_STUBS
               Io=0x4:FACILITY_IO_ERROR_CODE
              )

LanguageNames=(English=0x409:MSG00409)


; // The following are the categories of events.

MessageIdTypedef=WORD

MessageId=0x1
SymbolicName=PASSWORD_FILTER_EVENTS
Language=English
CustomPasswordFilter
.


; // The following are the message definitions.

MessageIdTypedef=DWORD

MessageId=0x100
Severity=Informational
Facility=Runtime
SymbolicName=PATTERN_RELOADED
Language=English
Pattern file reloaded successfully. Loaded Patterns: %1.
.

MessageId=0x101
Severity=Error
Facility=Runtime
SymbolicName=PATTERN_ERROR
Language=English
Failed to open  pattern file. Loading defaults.
.

MessageId=0x102
Severity=Warning
Facility=Runtime
SymbolicName=PATTERN_FILTER
Language=English
Password didn't pass the filter.  AccountName: %1, FullName: %2, Pattern: %3.
.
