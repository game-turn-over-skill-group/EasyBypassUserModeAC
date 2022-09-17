# EasyBypassUserModeAC
EasyBypassUserModeAC is a x64 Windows kernel driver intented to hide debuggers from user-mode anti-cheats. EasyBypassUserModeAC hooks shadow SSDT to stop anti-cheats from querying the hwnd of running debuggers, and hooks SSDT to bypass anti-debug and hide the process information of running debuggers.
