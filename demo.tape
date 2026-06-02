Output demo.gif

Set FontSize 16
Set Width 600
Set Height 300

Type "RustyAlias, Wildcard DNS for any IP Address"
Sleep 0.5s
Ctrl+C
Sleep 0.5s

Type "dig node1.10.13.37.1.ns.addr.se +tcp +short"
Enter
Sleep 1s
Enter

Type "dig node1.10.13.37.2.ns.addr.se +tcp +short"
Enter
Sleep 1s
Enter

Type "dig version txt +tcp +short @ns.addr.se"
Enter
Sleep 1s
Enter

Sleep 2s
