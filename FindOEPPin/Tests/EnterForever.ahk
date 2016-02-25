
;This will visit all windows on the entire system and display info about each of them:

#Persistent

#WinActivateForce

x := (A_ScreenWidth // 2)
y := (A_ScreenHeight // 2)
MouseMove, x, y
Send, {Esc}
Send, {Esc}

SetTimer, getWindows, 5000
Return

getWindows:
Click
Click
Send, {Enter}
Send, {Esc}
Click,
MouseMove, x, y
Return               



