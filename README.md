Assembling

ml64.exe /c /nologo /Zi /Fo"x64\Debug\main.obj" /I"C:\masm32\include" "C:\Users\6lady\source\repos\ml64example2\ml64example2\main.asm"

link /SUBSYSTEM:CONSOLE /ENTRY:_main /OUT:x64\Debug\main.exe x64\Debug\main.obj kernel32.lib user32.lib
