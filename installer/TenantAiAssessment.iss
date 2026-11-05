#define AppName "Tenant AI Security Assessment"
#define AppVersion "1.0.0"
#define AppPublisher "VPaulC"
#define AppId "A52A265E-9307-43EA-83E0-12DB96560F2A"

[Setup]
AppId={{{#AppId}}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={localappdata}\Programs\Tenant AI Security Assessment
DefaultGroupName={#AppName}
PrivilegesRequired=lowest
OutputDir=Output
OutputBaseFilename=Tenant-AI-Security-Assessment-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
Uninstallable=yes

[Files]
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\SKILL.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Invoke-TenantAiAssessment.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\collect_graph.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\analyse_findings.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\brand-template.potx"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\branding.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\checks-catalogue.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\cis-benchmark.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\cis-mapping.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\licensing-map.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\report-outlines.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\README"; Filename: "{app}\README.md"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
