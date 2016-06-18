rule msg_box : test
{
    meta:
        description = "This is an example"
        thread_level = 3
        in_the_wild = true
    strings:
        $a = {E9 B6 15 00 00 E9 71 03 00 00 E9 3C 14 00 00}
        $b = "Hello"
    condition:
        $a or $b
}