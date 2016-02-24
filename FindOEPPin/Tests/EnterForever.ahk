
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
    WinGetClass, this_class, ahk_id %this_id%
    WinGetTitle, this_title, ahk_id %this_id%
    ;MsgBox, 4, , Visiting All Windows`n%a_index% of %id%`nahk_id %this_id%`nahk_class %this_class%`n%this_title%`n`nContinue?
    IfMsgBox, NO, break
    Send, {Enter}
}
Return               



