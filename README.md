# local-reverse-shell
Simple remote shell

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
