
;This will visit all windows on the entire system and display info about each of them:

#Persistent

WinGet, id, list,,, Program Manager

SetTimer, getWindows, 5000
Return

getWindows:
Loop, %id%
{
    this_id := id%A_Index%
    WinActivate, ahk_id %this_id%
    Send, {Enter}
}
Return               

