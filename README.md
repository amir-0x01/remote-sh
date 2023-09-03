# remote-shell
Simple remote shell

This was written when learning socket programming in C++.
This should not be used in a production environment, and contains known vulnerabilities.

./mainsh [port] && ./secondsh [port] [host]

Commands:
- disconnect, ends the socket however secondSH is still listening
- stoprocess, ends the socket and terminates secondSH
- logs, view previous commands
- sudo, run as sudo
- download [dir], download text based files
- upload [file dir] [upload dir] [name], upload text based files
- downloadir [dir], change download directory
- showdownloadir, displays download directory
