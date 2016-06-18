import "pe"
rule imports : imp
{
    meta:
        description = "This is an example"
        thread_level = 3
        in_the_wild = true

    condition:
        pe.imports("kernel32.dll", "TerminateProcess") or pe.imports("user32.dll", "MessageBoxW")
        or pe.imports("user32.dll", "testtests")
}