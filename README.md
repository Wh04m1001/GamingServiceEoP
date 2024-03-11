# GamingServiceEoP
Exploit for arbitrary folder move in GamingService component of Xbox.
GamingService is not default service.
If service is installed on system it allows low privilege users to escalate to system.

During the process of changing directory the Gaming Services service will try to open C:\XboxGames\GameSave\Content\MicrosoftGame.Config file, if the file exists the gaming service will try to move whole C:\XboxGames\GameSave folder. It does that by calling MoveFileW API call while impersonating calling user.

If gaming service fails to move folder due to access denied error it will revert impersonation and perform the move operation as system.
As the C:\XboxGames folder gives modify permissions to authenticated users group (even if it does not the user can change it to directory that is fully controlled by that user) user can delete c:\xboxgames folder, create new one, drop arbitrary dll inside C:\XboxGames\GameSave folder and add deny delete ACL for itself so that move operation fails while impersonating user.

As result of my previous report MSRC included few checks/mitigations before moving folder.
1. Before moving folder service checks if destionation folder is reparse point
2. Lockdown both source and destination directory by creating temporary file (.tmp_ + digit)  with FILE_FLAG_DELETE_ON_CLOSE flag and share set to none so that user cant delete file

The implementation of these measures is flawed as the check for junction is done before locking the directory. This can be abused to trick service that new installation directory is safe but then turning it into a junction point just before service move folder and redirect it to c:\windows\system32\spool\drivers\x64 directory.
The time window is small but can be incresed by creating multiple .tmp_ +digit files as service specify CREATE_ALWAYS and will fail to create file if exist and will continue to increase digit untill file is successfuly created.

The exploit abuse spooler service to load arbitrary DLL as system

PoC
![video](https://github.com/Wh04m1001/GamingServiceEoP/blob/main/poc2.mp4)

MSRC stating no security boundry is crossed

![image](https://github.com/Wh04m1001/GamingServiceEoP/blob/main/msrc.png)
