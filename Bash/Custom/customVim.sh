#!/bin/bash

apt-get install vim
    if [[ ! -f /etc/vim/vimrc.local ]]; then
        echo -e "syntax on \
            \nset noet ci pi sts=0 sw=4 ts=4 \
            \nset cursorline \
            \nfiletype plugin indent on \
            \nset t_Co=256 \
            \nset background=dark \
            \nset titlestring=%f title \
            \nset nobk nowb noswf \
            \nset tabstop=2 \
            \nset shiftwidth=2 \
            \nset expandtab \
            " > /etc/vim/vimrc.local
    fi
exit 0
