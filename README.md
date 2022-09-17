# EasyBypassUserModeAC
EasyBypassUserModeAC is a x64 Windows kernel driver intented to hide debuggers from user-mode anti-cheats. EasyBypassUserModeAC hooks shadow SSDT to stop anti-cheats from querying the hwnd of running debuggers, and hooks SSDT to bypass anti-debug and hide the process information of running debuggers.

As you can see, almost the code can be found on Google and github, I just add shadow SSDT in TitanHide, but the main goal here is to show how to write a Windows kernel driver. To get more detail about SSDT hooking, please refer to the original repository.

# Reference
* [TitanHide](https://github.com/mrexodia/TitanHide)
* [Hook SSDT(Shadow)](https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/ssdt-hook)
* [Kernel Mode Driver Framework >> C/C++ (PNP)](https://steward-fu.github.io/website/driver/kmdf/cpp_pnp_thread.htm)

# Demo
![](demo.gif)
