# plistcarver
Python script to carve binary plist files

This is my first "significant" python project, so I'm sure there's lots of room for improvement.

While doing research and forensic examinations, there have been times that I have found binary plist files "hiding" within database blob files, other plist files, or just random files on the system, sometimes even multiple plist files within the same blob, and while it was possible to manually try and carve those files, I figured there had to be a better. Since I wasn't able to find a program to do the carving for me, I decided to embark on this adventure.

This script is intended to carve binary plist files from other files such as databases or other binary plist files.
